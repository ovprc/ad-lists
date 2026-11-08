#!/usr/bin/env python3
"""Read-only S-UI-X v1.5.11 account bridge, accessible only through the VPN.

Run: python3 /usr/local/lib/mintun/mintun-account-bridge.py \
    --database /usr/local/s-ui/db/s-ui.db
Binds 127.0.0.1:2099; --port is solely for isolated smoke testing. No bind-host option.
For panel templates containing loopback dial endpoints, supply --public-host
with the externally reachable VPN host. Repeat --port-map ID:INTERNAL:PUBLIC
only for known fronted inbounds; stale internal ports fail closed. These options
project client dial endpoints only: the HTTP listener never becomes public.
The service account needs directory traversal and read access to the database
and its existing -wal/-shm files, not root, panel credentials, or DB write access.
Never expose this port publicly or add a direct-HTTP client fallback.

Source contracts (pinned to v1.5.11):
https://github.com/deposist/s-ui-x/blob/v1.5.11/database/model/model.go
https://github.com/deposist/s-ui-x/blob/v1.5.11/service/client.go
https://github.com/deposist/s-ui-x/blob/v1.5.11/service/stats.go
https://github.com/deposist/s-ui-x/blob/v1.5.11/util/outJson.go
https://github.com/deposist/s-ui-x/blob/v1.5.11/sub/jsonService.go

Inbounds are numeric database IDs, not array indices or tags. out_json is the
finalized client template; no server TLS/options/links tables are consulted.
As upstream does, addrs override server/port and shallow-merge TLS. This catalog
has one entry per inbound, so its first configured address is deterministic and
its original logical tag never receives upstream's subscription index suffix.
Malformed REALITY credentials make an inbound unavailable; no key is guessed.
"""

import argparse
import base64
import binascii
import hashlib
import ipaddress
import hmac
import json
from pathlib import Path
import re
import socket
import socketserver
import sqlite3
import sys
import threading
import time
import uuid


DEFAULT_DATABASE = "/usr/local/s-ui/db/s-ui.db"
MAX_RESPONSE = 512 * 1024
MAX_JSON = 32 * 1024
MAX_ACCOUNT_JSON = 64 * 1024
MAX_INBOUNDS = 128
MAX_HEADERS = 8192
MAX_HEADER_LINES = 32
REQUEST_TIMEOUT = 5.0
DB_TIMEOUT = 1.0
SUPPORTED = frozenset(("vless", "vmess", "tuic", "hysteria2"))
FINGERPRINTS = frozenset(("chrome", "firefox", "edge", "safari", "360", "qq", "ios", "android", "random", "randomized"))


class Unauthorized(Exception):
    """No unique, canonical authenticated identity."""


class BridgeUnavailable(Exception):
    """Database or response cannot safely satisfy the account contract."""


class InvalidTemplate(Exception):
    """An inbound is unavailable; exception text never contains source data."""


def validate_public_host(value):
    """Validate a dial host without DNS queries or exposing it in diagnostics."""
    if not isinstance(value, str) or not value or len(value) > 253 or value != value.strip():
        raise ValueError("invalid public dial host")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        host = value.lower().removesuffix(".")
        labels = host.split(".")
        if len(labels) < 2 or all(label.isdigit() for label in labels):
            raise ValueError("invalid public dial host") from None
        if labels[-1] in ("localhost", "local", "lan", "internal", "home", "onion"):
            raise ValueError("invalid public dial host") from None
        if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
            raise ValueError("invalid public dial host") from None
        return host
    if not address.is_global or address.is_multicast or address.is_reserved or address.is_unspecified or "%" in value:
        raise ValueError("invalid public dial host")
    return str(address)


def validate_port_maps(value):
    if value is None:
        return {}
    if not isinstance(value, dict) or len(value) > MAX_INBOUNDS:
        raise ValueError("invalid inbound port mapping")
    result = {}
    for ident, ports in value.items():
        if type(ident) is not int or not 0 < ident <= (1 << 64) - 1:
            raise ValueError("invalid inbound port mapping")
        if not isinstance(ports, (tuple, list)) or len(ports) != 2:
            raise ValueError("invalid inbound port mapping")
        if any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
            raise ValueError("invalid inbound port mapping")
        result[ident] = tuple(ports)
    return result


def parse_port_map(value):
    if not isinstance(value, str) or len(value) > 32 or not re.fullmatch(r"[1-9][0-9]*:[1-9][0-9]*:[1-9][0-9]*", value):
        raise argparse.ArgumentTypeError("port map must be ID:INTERNAL_PORT:PUBLIC_PORT")
    ident, internal, public = (int(part) for part in value.split(":"))
    try:
        validate_port_maps({ident: (internal, public)})
    except ValueError:
        raise argparse.ArgumentTypeError("invalid inbound ID or mapped port range") from None
    return ident, (internal, public)


def _loopback(value):
    if not isinstance(value, str):
        return False
    if value.lower().removesuffix(".") == "localhost":
        return True
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_loopback or (
        isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None
        and address.ipv4_mapped.is_loopback
    )


def _project_endpoint(outbound, ident, public_host, port_maps):
    original_server = outbound.get("server")
    if not _loopback(original_server):
        return  # Explicit nonloopback Addrs/template endpoints remain authoritative.
    if public_host is None:
        raise InvalidTemplate()
    if ident in port_maps:
        internal_port, public_port = port_maps[ident]
        original_port = outbound.get("server_port")
        if type(original_port) is not int or original_port != internal_port:
            raise InvalidTemplate()
        outbound["server_port"] = public_port
    outbound["server"] = public_host


def canonical_uuid(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", value):
        return False
    try:
        parsed = uuid.UUID(value)
        return parsed.int != 0 and hmac.compare_digest(str(parsed), value)
    except (ValueError, AttributeError):
        return False


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _json(raw, cap=MAX_JSON):
    if not isinstance(raw, (str, bytes)) or len(raw) > cap:
        raise ValueError("invalid JSON size")
    return json.loads(raw, object_pairs_hook=_pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid JSON number")))


def _uint(value):
    if type(value) is not int or not 0 <= value <= (1 << 64) - 1:
        raise BridgeUnavailable()
    return value


def _flag(value):
    if type(value) is not int or value not in (0, 1):
        raise BridgeUnavailable()
    return bool(value)


def _text(value, limit=1024, multiline=False):
    if not isinstance(value, str) or len(value.encode("utf-8")) > limit:
        raise InvalidTemplate()
    if any(ord(c) < 32 and not (multiline and c in "\r\n\t") or ord(c) == 127 for c in value):
        raise InvalidTemplate()
    if "PRIVATE KEY" in value.upper():
        raise InvalidTemplate()
    return value


def _keys(value, allowed):
    if not isinstance(value, dict) or value.keys() - set(allowed.split()):
        raise InvalidTemplate()


def _strings(value, limit=32, multiline=False):
    if not isinstance(value, list) or len(value) > limit:
        raise InvalidTemplate()
    for item in value:
        _text(item, MAX_JSON if multiline else 1024, multiline)


def _booleans(value, names):
    for name in names.split():
        if name in value and type(value[name]) is not bool:
            raise InvalidTemplate()


def _positive(value, maximum=(1 << 32) - 1):
    if type(value) is not int or not 0 < value <= maximum:
        raise InvalidTemplate()


def _tls(tls):
    _keys(tls, "enabled server_name insecure alpn min_version max_version cipher_suites certificate certificate_public_key_sha256 utls reality ech")
    _booleans(tls, "enabled insecure")
    if tls.get("insecure", False):
        raise InvalidTemplate()
    for field in ("server_name", "min_version", "max_version"):
        if field in tls:
            _text(tls[field])
    for field in ("alpn", "cipher_suites", "certificate_public_key_sha256"):
        if field in tls:
            _strings(tls[field])
    if "certificate" in tls:
        _strings(tls["certificate"], limit=256, multiline=True)
        certificate = "\n".join(tls["certificate"])
        if "-----BEGIN CERTIFICATE-----" not in certificate or "-----END CERTIFICATE-----" not in certificate:
            raise InvalidTemplate()
    if "utls" in tls:
        utls = tls["utls"]
        _keys(utls, "enabled fingerprint")
        _booleans(utls, "enabled")
        if utls.get("fingerprint") not in FINGERPRINTS:
            raise InvalidTemplate()
    if "reality" in tls:
        reality = tls["reality"]
        _keys(reality, "enabled public_key short_id")
        _booleans(reality, "enabled")
        if reality.get("enabled", False):
            key = reality.get("public_key")
            short_id = reality.get("short_id")
            if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", key):
                raise InvalidTemplate()
            try:
                decoded = base64.b64decode(key + "=", altchars=b"-_", validate=True)
            except (ValueError, binascii.Error):
                raise InvalidTemplate() from None
            if len(decoded) != 32 or base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != key:
                raise InvalidTemplate()
            if not isinstance(short_id, str) or not re.fullmatch(r"(?:[0-9a-fA-F]{2}){0,8}", short_id):
                raise InvalidTemplate()
        else:
            for key in ("public_key", "short_id"):
                if key in reality:
                    _text(reality[key])
    if "ech" in tls:
        ech = tls["ech"]
        _keys(ech, "enabled config pq_signature_schemes_enabled dynamic_record_sizing_disabled")
        _booleans(ech, "enabled pq_signature_schemes_enabled dynamic_record_sizing_disabled")
        if "config" in ech:
            _strings(ech["config"], multiline=True)
        if ech.get("enabled") and not ech.get("config"):
            raise InvalidTemplate()


def _transport(transport):
    _keys(transport, "type host path method headers max_early_data early_data_header_name service_name idle_timeout ping_timeout permit_without_stream")
    kind = transport.get("type")
    allowed = {
        "tcp": "type", "quic": "type",
        "ws": "type path headers max_early_data early_data_header_name",
        "http": "type host path method headers idle_timeout ping_timeout",
        "httpupgrade": "type host path headers",
        "grpc": "type service_name idle_timeout ping_timeout permit_without_stream",
    }
    if kind not in allowed:
        raise InvalidTemplate()
    _keys(transport, allowed[kind])
    for key, value in transport.items():
        if key == "headers":
            if not isinstance(value, dict) or len(value) > 32:
                raise InvalidTemplate()
            for name, header in value.items():
                _text(name, 128)
                if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) or name.lower() in ("authorization", "proxy-authorization", "cookie", "set-cookie"):
                    raise InvalidTemplate()
                if isinstance(header, list):
                    _strings(header)
                else:
                    _text(header)
        elif key == "host" and isinstance(value, list):
            _strings(value)
        elif key == "max_early_data":
            if type(value) is not int or not 0 <= value <= 65536:
                raise InvalidTemplate()
        elif key == "permit_without_stream":
            _booleans(transport, key)
        else:
            _text(value)


def _validate_outbound(outbound, protocol):
    common = ("type tag server server_port network tls transport multiplex connect_timeout "
              "tcp_fast_open tcp_multi_path tcp_keep_alive tcp_keep_alive_interval udp_fragment ")
    fields = {
        "vless": "uuid flow packet_encoding",
        "vmess": "uuid security alter_id global_padding authenticated_length packet_encoding",
        "tuic": "uuid password congestion_control udp_relay_mode udp_over_stream zero_rtt_handshake heartbeat",
        "hysteria2": "password up_mbps down_mbps obfs server_ports hop_interval",
    }
    _keys(outbound, common + fields[protocol])
    if outbound.get("type") != protocol:
        raise InvalidTemplate()
    tag = _text(outbound.get("tag"), 128)
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", tag):
        raise InvalidTemplate()
    server = _text(outbound.get("server"), 253)
    if not server or any(c.isspace() for c in server) or any(c in server for c in "/\\@?#") or server in ("0.0.0.0", "::"):
        raise InvalidTemplate()
    _positive(outbound.get("server_port"), 65535)
    if "network" in outbound and outbound["network"] not in ("tcp", "udp", "tcp,udp"):
        raise InvalidTemplate()
    _booleans(outbound, "tcp_fast_open tcp_multi_path udp_fragment")
    for field in ("connect_timeout", "tcp_keep_alive", "tcp_keep_alive_interval"):
        if field in outbound:
            _text(outbound[field], 64)
    if "tls" in outbound:
        _tls(outbound["tls"])
    if protocol in ("tuic", "hysteria2"):
        if not isinstance(outbound.get("tls"), dict) or outbound["tls"].get("enabled") is not True or "transport" in outbound or "multiplex" in outbound:
            raise InvalidTemplate()
        if "utls" in outbound["tls"] or "reality" in outbound["tls"]:
            raise InvalidTemplate()
    if "transport" in outbound:
        _transport(outbound["transport"])
    if "multiplex" in outbound:
        mux = outbound["multiplex"]
        _keys(mux, "enabled protocol max_connections min_streams max_streams padding brutal")
        _booleans(mux, "enabled padding")
        if "protocol" in mux and mux["protocol"] not in ("smux", "yamux", "h2mux"):
            raise InvalidTemplate()
        for field in ("max_connections", "min_streams", "max_streams"):
            if field in mux:
                _positive(mux[field])
        if "brutal" in mux:
            _keys(mux["brutal"], "enabled up_mbps down_mbps")
            _booleans(mux["brutal"], "enabled")
            for field in ("up_mbps", "down_mbps"):
                if field in mux["brutal"]:
                    _positive(mux["brutal"][field])
    if protocol in ("vless", "vmess", "tuic") and not canonical_uuid(outbound.get("uuid")):
        raise InvalidTemplate()
    if protocol in ("tuic", "hysteria2"):
        if not _text(outbound.get("password"), 1024):
            raise InvalidTemplate()
    if "flow" in outbound and outbound["flow"] not in ("", "xtls-rprx-vision"):
        raise InvalidTemplate()
    if "packet_encoding" in outbound and outbound["packet_encoding"] not in ("", "packetaddr", "xudp"):
        raise InvalidTemplate()
    _booleans(outbound, "global_padding authenticated_length udp_over_stream zero_rtt_handshake")
    if "alter_id" in outbound and (type(outbound["alter_id"]) is not int or not 0 <= outbound["alter_id"] <= 65535):
        raise InvalidTemplate()
    if "security" in outbound and outbound["security"] not in ("auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305"):
        raise InvalidTemplate()
    if "congestion_control" in outbound and outbound["congestion_control"] not in ("cubic", "new_reno", "bbr"):
        raise InvalidTemplate()
    if "udp_relay_mode" in outbound and outbound["udp_relay_mode"] not in ("native", "quic"):
        raise InvalidTemplate()
    for field in ("heartbeat", "hop_interval"):
        if field in outbound:
            _text(outbound[field], 64)
    for field in ("up_mbps", "down_mbps"):
        if field in outbound:
            _positive(outbound[field])
    if "server_ports" in outbound:
        _strings(outbound["server_ports"])
        for ports in outbound["server_ports"]:
            if not re.fullmatch(r"[0-9]{1,5}(?::[0-9]{1,5})?", ports):
                raise InvalidTemplate()
            numbers = [int(number) for number in ports.split(":")]
            if any(not 1 <= number <= 65535 for number in numbers) or numbers[0] > numbers[-1]:
                raise InvalidTemplate()
    if "obfs" in outbound:
        _keys(outbound["obfs"], "type password")
        if outbound["obfs"].get("type") != "salamander" or not _text(outbound["obfs"].get("password")):
            raise InvalidTemplate()


def materialize(row, config, public_host=None, port_maps=None):
    protocol = row["type"]
    try:
        outbound = _json(row["out_json"])
        if not isinstance(outbound, dict) or outbound.get("type") != protocol:
            raise InvalidTemplate()
        # Preserve the DB's stable logical identity, never subscription suffixes.
        if outbound.get("tag") != row["tag"]:
            raise InvalidTemplate()
        if outbound.get("transport") == {}:
            del outbound["transport"]
        addresses = _json(row["addrs"]) if row["addrs"] is not None else []
        if addresses is None:
            addresses = []  # JSON null is upstream's empty []map representation.
        if not isinstance(addresses, list) or len(addresses) > 128:
            raise InvalidTemplate()
        if addresses:
            address = addresses[0]
            _keys(address, "server server_port tls remark")
            outbound["server"] = address.get("server")
            outbound["server_port"] = address.get("server_port")
            if "tls" in address:
                if not isinstance(address["tls"], dict) or not isinstance(outbound.get("tls", {}), dict):
                    raise InvalidTemplate()
                outbound["tls"] = {**outbound.get("tls", {}), **address["tls"]}
        _project_endpoint(outbound, row["id"], public_host, port_maps or {})
        credentials = config.get(protocol)
        if not isinstance(credentials, dict):
            raise InvalidTemplate()
        if protocol in ("vless", "vmess", "tuic"):
            outbound["uuid"] = credentials.get("uuid")
        if protocol in ("tuic", "hysteria2"):
            outbound["password"] = credentials.get("password")
        if protocol == "vless":
            outbound.pop("flow", None)
            if row["tls_id"] and outbound.get("transport", {}).get("type", "tcp") in ("", "tcp"):
                if "flow" in credentials:
                    outbound["flow"] = credentials["flow"]
        if protocol == "vmess" and "security" in credentials:
            outbound["security"] = credentials["security"]
        if protocol in ("tuic", "hysteria2") and isinstance(outbound.get("tls"), dict):
            # Panel templates may retain disabled TCP-only placeholders.
            for field in ("utls", "reality"):
                if outbound["tls"].get(field) == {"enabled": False}:
                    del outbound["tls"][field]
        _validate_outbound(outbound, protocol)
        result = json.dumps(outbound, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        if len(result.encode("utf-8")) > MAX_JSON:
            raise InvalidTemplate()
        return result
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, UnicodeError, InvalidTemplate):
        raise InvalidTemplate() from None


class AccountStore:
    def __init__(self, database, *, public_host=None, port_maps=None):
        self.database = Path(database).resolve()
        self.public_host = validate_public_host(public_host) if public_host is not None else None
        self.port_maps = validate_port_maps(port_maps)

    def connect(self):
        db = None
        try:
            db = sqlite3.connect(self.database.as_uri() + "?mode=ro", uri=True, timeout=0.25)
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA query_only=ON")
            db.execute("PRAGMA trusted_schema=OFF")
            deadline = time.monotonic() + DB_TIMEOUT
            db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
            return db
        except (OSError, sqlite3.Error):
            if db is not None:
                db.close()
            raise BridgeUnavailable() from None

    def snapshot(self, token, now=None):
        if not canonical_uuid(token):
            raise Unauthorized()
        db = self.connect()
        try:
            # The predicate extracts UUIDs only. Other clients' complete config,
            # protocol passwords, names, links, and server TLS are never selected.
            def matches(value):
                return int(isinstance(value, str) and len(value) == 36 and
                           hmac.compare_digest(value.encode("utf-8"), token.encode("ascii")))
            db.create_function("account_matches", 1, matches, deterministic=True)
            db.execute("BEGIN")
            identities = db.execute("""
                SELECT id FROM clients WHERE account_matches(
                    CASE WHEN length(config) <= ? AND json_valid(config)
                    THEN json_extract(config, '$.vless.uuid') ELSE NULL END
                ) LIMIT 2
            """, (MAX_ACCOUNT_JSON,)).fetchall()
            if len(identities) != 1:
                raise Unauthorized()
            client = db.execute("""
                SELECT enable, config, inbounds, volume, expiry, up, down, delay_start
                FROM clients WHERE id=? AND length(config)<=? AND length(inbounds)<=?
            """, (identities[0]["id"], MAX_ACCOUNT_JSON, MAX_JSON)).fetchone()
            if client is None:
                raise BridgeUnavailable()
            enabled, delay = _flag(client["enable"]), _flag(client["delay_start"])
            volume, up, down = (_uint(client[key]) for key in ("volume", "up", "down"))
            expiry = client["expiry"]
            if type(expiry) is not int or not -(1 << 63) <= expiry < (1 << 63):
                raise BridgeUnavailable()
            config = _json(client["config"], MAX_ACCOUNT_JSON)
            assigned = _json(client["inbounds"])
            if not isinstance(config, dict) or not isinstance(assigned, list) or len(assigned) > MAX_INBOUNDS:
                raise BridgeUnavailable()
            if any(type(ident) is not int or not 0 < ident <= (1 << 64) - 1 for ident in assigned) or len(set(assigned)) != len(assigned):
                raise BridgeUnavailable()
            assigned = set(assigned)
            now = int(time.time()) if now is None else now
            metadata = db.execute("SELECT id,type,tag FROM inbounds ORDER BY id LIMIT ?", (MAX_INBOUNDS + 1,)).fetchall()
            if len(metadata) > MAX_INBOUNDS:
                raise BridgeUnavailable()
            account_reason = ""
            if not enabled:
                account_reason = "Account disabled"
            elif expiry > 0 and expiry < now:
                account_reason = "Account expired"
            elif volume > 0 and up + down > volume:
                account_reason = "Traffic limit exceeded"
            entries = []
            for meta in metadata:
                ident = _uint(meta["id"])
                if not ident:
                    raise BridgeUnavailable()
                _text(meta["tag"], 256)
                protocol = _text(meta["type"], 32)
                reason = account_reason
                if not reason and ident not in assigned:
                    reason = "Not assigned to this account"
                if not reason and protocol not in SUPPORTED:
                    reason = "Unsupported protocol"
                outbound = None
                if not reason:
                    row = db.execute("""
                        SELECT id,type,tag,tls_id,
                            CASE WHEN addrs IS NULL THEN NULL WHEN length(addrs)<=? THEN addrs ELSE 'invalid' END AS addrs,
                            CASE WHEN length(out_json)<=? THEN out_json ELSE NULL END AS out_json
                        FROM inbounds WHERE id=?
                    """, (MAX_JSON, MAX_JSON, ident)).fetchone()
                    if row is None:
                        raise BridgeUnavailable()
                    try:
                        outbound = materialize(row, config, self.public_host, self.port_maps)
                    except InvalidTemplate:
                        reason = "Client configuration unavailable"
                entries.append({"id": ident, "label": meta["tag"], "protocol": protocol,
                                "available": not bool(reason), "unavailableReason": reason,
                                "outboundJson": outbound})
            result = {"format": 1, "generatedAt": now,
                      "subject": hashlib.sha256(token.encode("ascii")).hexdigest(),
                      "enabled": enabled, "expiresAt": expiry if expiry > 0 else None,
                      # Upstream ignores negative expiry when delay_start=false;
                      # conservatively expose that ambiguous state as pending.
                      "activationPending": delay or expiry < 0,
                      "trafficLimitBytes": volume if volume > 0 else None,
                      "uploadBytes": up, "downloadBytes": down, "inbounds": entries}
            encode_snapshot(result)
            return result
        except Unauthorized:
            raise
        except (sqlite3.Error, ValueError, TypeError, InvalidTemplate, RecursionError, UnicodeError):
            raise BridgeUnavailable() from None
        finally:
            db.close()


def encode_snapshot(snapshot):
    try:
        encoded = json.dumps(snapshot, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise BridgeUnavailable() from None
    if len(encoded) > MAX_RESPONSE:
        raise BridgeUnavailable()
    return encoded


class _RateLimit:
    def __init__(self):
        self.lock = threading.Lock()
        self.tokens = 20.0
        self.updated = time.monotonic()

    def admit(self):
        with self.lock:
            now = time.monotonic()
            self.tokens = min(20.0, self.tokens + now - self.updated)
            self.updated = now
            if self.tokens < 1:
                return False
            self.tokens -= 1
            return True


class _Request(socketserver.StreamRequestHandler):
    def _reply(self, status, body):
        phrases = {200: "OK", 400: "Bad Request", 401: "Unauthorized", 404: "Not Found",
                   405: "Method Not Allowed", 408: "Request Timeout", 429: "Too Many Requests",
                   431: "Request Header Fields Too Large", 503: "Service Unavailable"}
        head = ("HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n"
                "Cache-Control: no-store\r\nPragma: no-cache\r\nX-Content-Type-Options: nosniff\r\n"
                "Connection: close\r\n" % (status, phrases[status], len(body)))
        if status == 401:
            head += 'WWW-Authenticate: Bearer\r\n'
        self.wfile.write(head.encode("ascii") + b"\r\n" + body)

    def handle(self):
        try:
            self._handle_request()
        except (TimeoutError, socket.timeout):
            self._reply(408, b'{"error":"request timeout"}')
        except (ConnectionError, OSError):
            pass  # No request/token/exception logging, including broken pipes.
        except Exception:
            # Database and parser exceptions never become secret-bearing traces.
            try:
                self._reply(503, b'{"error":"service unavailable"}')
            except (ConnectionError, OSError):
                pass

    def _handle_request(self):
        if not self.server.rate_limit.admit():
            self._reply(429, b'{"error":"rate limited"}')
            return
        deadline = time.monotonic() + REQUEST_TIMEOUT
        total = 0

        def line(limit):
            nonlocal total
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError()
            self.connection.settimeout(remaining)
            value = self.rfile.readline(min(limit, MAX_HEADERS - total) + 1)
            total += len(value)
            if len(value) > limit or total > MAX_HEADERS:
                raise OverflowError()
            if not value.endswith(b"\r\n"):
                raise ValueError()
            return value[:-2]

        try:
            request = line(1024).decode("ascii")
            parts = request.split(" ")
            if len(parts) != 3 or parts[2] not in ("HTTP/1.0", "HTTP/1.1"):
                raise ValueError()
            method, path, version = parts
            headers = {}
            duplicate_auth = False
            for _ in range(MAX_HEADER_LINES + 1):
                raw = line(2048)
                if not raw:
                    break
                if len(headers) >= MAX_HEADER_LINES or raw[:1] in (b" ", b"\t"):
                    raise ValueError()
                name, separator, value = raw.partition(b":")
                if not separator or not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
                    raise ValueError()
                name = name.decode("ascii").lower()
                value = value.decode("latin-1").strip(" \t")
                if any(ord(char) < 32 or ord(char) == 127 for char in value):
                    raise ValueError()
                if name in headers:
                    if name == "authorization":
                        duplicate_auth = True
                    else:
                        raise ValueError()
                headers[name] = value
            else:
                raise OverflowError()
        except OverflowError:
            self._reply(431, b'{"error":"headers too large"}')
            return
        except (ValueError, UnicodeError):
            self._reply(400, b'{"error":"invalid request"}')
            return
        if "origin" in headers or "transfer-encoding" in headers or headers.get("content-length", "0") != "0":
            self._reply(400, b'{"error":"invalid request"}')
            return
        expected_host = "127.0.0.1:" + str(self.server.server_address[1])
        if headers.get("host") not in (expected_host, "127.0.0.1" if self.server.server_address[1] == 80 else expected_host):
            self._reply(400, b'{"error":"invalid request"}')
            return
        authorization = headers.get("authorization", "")
        token = authorization[7:] if authorization.startswith("Bearer ") else ""
        if duplicate_auth or not canonical_uuid(token):
            self._reply(401, b'{"error":"unauthorized"}')
            return
        if path != "/v1/account":
            self._reply(404, b'{"error":"not found"}')
            return
        if method != "GET":
            self._reply(405, b'{"error":"method not allowed"}')
            return
        # Restore a bounded write timeout after the absolute header deadline.
        self.connection.settimeout(REQUEST_TIMEOUT)
        try:
            body = encode_snapshot(self.server.store.snapshot(token))
        except Unauthorized:
            self._reply(401, b'{"error":"unauthorized"}')
            return
        except BridgeUnavailable:
            self._reply(503, b'{"error":"service unavailable"}')
            return
        self._reply(200, body)


class BridgeServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    block_on_close = True
    allow_reuse_address = True
    request_queue_size = 16

    def __init__(self, database=DEFAULT_DATABASE, port=2099, *, public_host=None, port_maps=None):
        self.store = AccountStore(database, public_host=public_host, port_maps=port_maps)
        self.rate_limit = _RateLimit()
        self._slots = threading.BoundedSemaphore(8)
        super().__init__(("127.0.0.1", port), _Request)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def handle_error(self, request, client_address):
        pass  # socketserver's default traceback could disclose request context.


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read-only VPN-private loopback account bridge")
    parser.add_argument("--database", default=DEFAULT_DATABASE, help="read-only S-UI SQLite database")
    parser.add_argument("--port", type=int, default=2099, help="loopback port (override for isolated smoke tests only)")
    parser.add_argument("--public-host", help="public VPN dial hostname/IP for internal templates; never changes HTTP bind")
    parser.add_argument("--port-map", type=parse_port_map, action="append", default=[],
                        metavar="ID:INTERNAL:PUBLIC", help="guarded internal inbound port projection; repeatable")
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    port_maps = {}
    for ident, ports in args.port_map:
        if ident in port_maps:
            parser.error("duplicate inbound ID in port maps")
        port_maps[ident] = ports
    try:
        public_host = validate_public_host(args.public_host) if args.public_host is not None else None
        port_maps = validate_port_maps(port_maps)
    except ValueError:
        parser.error("invalid public dial host or inbound port mapping")
    try:
        with BridgeServer(args.database, args.port, public_host=public_host, port_maps=port_maps) as server:
            server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        return 0
    except (OSError, BridgeUnavailable):
        print("Account bridge could not start; check loopback port and read-only database permissions.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
