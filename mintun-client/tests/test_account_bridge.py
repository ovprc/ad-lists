"""Isolated stdlib tests; fixtures contain synthetic credentials only."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import socket
import sqlite3
import tempfile
import threading
import unittest


SPEC = importlib.util.spec_from_file_location(
    "mintun_account_bridge", Path(__file__).resolve().parents[1] / "scripts" / "mintun-account-bridge.py"
)
bridge = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bridge)
UUID_A = "11111111-1111-4111-8111-11111111111a"
UUID_B = "22222222-2222-4222-8222-22222222222b"
NOW = 1_800_000_000


def fixture_database(path):
    with contextlib.closing(sqlite3.connect(path)) as db, db:
        db.executescript("""
            CREATE TABLE clients (id INTEGER PRIMARY KEY, enable INTEGER, name TEXT,
                config BLOB, inbounds BLOB, links BLOB, volume INTEGER, expiry INTEGER,
                down INTEGER, up INTEGER, delay_start INTEGER, total_up INTEGER, total_down INTEGER);
            CREATE TABLE inbounds (id INTEGER PRIMARY KEY, type TEXT, tag TEXT,
                tls_id INTEGER, addrs BLOB, out_json BLOB, options BLOB);
            CREATE TABLE tls (id INTEGER PRIMARY KEY, server BLOB, client BLOB);
        """)
        for ident, token in ((1, UUID_A), (2, UUID_B)):
            config = {"vless": {"name": "private-account-name", "uuid": token, "flow": "xtls-rprx-vision"},
                      "tuic": {"name": "private-account-name", "uuid": token, "password": "own-tuic-" + str(ident)},
                      "hysteria2": {"name": "private-account-name", "password": "own-hy2-" + str(ident)}}
            db.execute("INSERT INTO clients VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (ident, 1, "private-account-name", json.dumps(config),
                        json.dumps([1, 3, 10, 12] if ident == 1 else [2, 11]), "[]",
                        1000, NOW + 86400, 250, 125, 0, 99999, 88888))
        for ident in range(1, 13):
            protocol = "vless" if ident <= 9 else ("tuic" if ident <= 11 else "hysteria2")
            outbound = {"type": protocol, "tag": "stable-" + str(ident), "server": "vpn.example.test",
                        "server_port": 4400 + ident, "tls": {"enabled": True, "server_name": "vpn.example.test"}}
            if protocol == "tuic":
                outbound.update(congestion_control="bbr", heartbeat="10s")
            db.execute("INSERT INTO inbounds VALUES (?,?,?,?,?,?,?)",
                       (ident, protocol, outbound["tag"], 1, "[]", json.dumps(outbound),
                        '{"users":[{"password":"SERVER-USERS-MUST-NOT-LEAK"}]}'))
        db.execute("INSERT INTO tls VALUES (1,?,?)",
                   ('{"key":["SERVER-PRIVATE-KEY-MUST-NOT-LEAK"]}', '{}'))


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "s-ui.db"
        fixture_database(self.path)
        self.store = bridge.AccountStore(self.path)

    def update_client(self, **fields):
        with contextlib.closing(sqlite3.connect(self.path)) as db, db:
            db.execute("UPDATE clients SET " + ",".join(key + "=?" for key in fields) + " WHERE id=1",
                       tuple(fields.values()))

    def update_inbound(self, ident=1, **fields):
        with contextlib.closing(sqlite3.connect(self.path)) as db, db:
            db.execute("UPDATE inbounds SET " + ",".join(key + "=?" for key in fields) + " WHERE id=?",
                       (*fields.values(), ident))

    def snapshot(self):
        return self.store.snapshot(UUID_A, now=NOW)

    def test_numeric_assignments_return_all_twelve_metadata_without_cross_account_credentials(self):
        snapshot = self.snapshot()
        self.assertEqual(len(snapshot["inbounds"]), 12)
        self.assertEqual([row["id"] for row in snapshot["inbounds"] if row["available"]], [1, 3, 10, 12])
        for row in snapshot["inbounds"]:
            self.assertEqual(row["label"], "stable-" + str(row["id"]))
            if row["available"]:
                self.assertEqual(json.loads(row["outboundJson"])["tag"], row["label"])
                self.assertEqual(row["unavailableReason"], "")
            else:
                self.assertIsNone(row["outboundJson"])
                self.assertTrue(row["unavailableReason"])
        wire = json.dumps(snapshot)
        for secret in (UUID_B, "own-tuic-2", "own-hy2-2", "private-account-name", "SERVER-USERS", "SERVER-PRIVATE"):
            self.assertNotIn(secret, wire)
        self.assertEqual(snapshot["subject"], hashlib.sha256(UUID_A.encode("ascii")).hexdigest())

    def test_protocol_credentials_are_injected_only_from_authenticated_account(self):
        rows = {row["id"]: json.loads(row["outboundJson"]) for row in self.snapshot()["inbounds"] if row["available"]}
        self.assertEqual(rows[1]["uuid"], UUID_A)
        self.assertEqual(rows[1]["flow"], "xtls-rprx-vision")
        self.assertEqual(rows[10]["uuid"], UUID_A)
        self.assertEqual(rows[10]["password"], "own-tuic-1")
        self.assertEqual(rows[12]["password"], "own-hy2-1")
        self.assertNotIn("uuid", rows[12])
        for outbound in rows.values():
            self.assertNotIn("name", outbound)

    def test_second_account_cannot_receive_first_accounts_assignments_or_credentials(self):
        snapshot = self.store.snapshot(UUID_B, now=NOW)
        self.assertEqual([row["id"] for row in snapshot["inbounds"] if row["available"]], [2, 11])
        wire = json.dumps(snapshot)
        for secret in (UUID_A, "own-tuic-1", "own-hy2-1"):
            self.assertNotIn(secret, wire)
        tuic = json.loads(snapshot["inbounds"][10]["outboundJson"])
        self.assertEqual((tuic["uuid"], tuic["password"]), (UUID_B, "own-tuic-2"))

    def test_plain_tcp_empty_transport_and_typed_dialer_options_are_preserved(self):
        template = {"type": "vless", "tag": "stable-1", "server": "vpn.example.test", "server_port": 443,
                    "tls": {"enabled": True}, "transport": {}, "connect_timeout": "5s",
                    "tcp_fast_open": True, "tcp_multi_path": False, "tcp_keep_alive": "30s",
                    "tcp_keep_alive_interval": "10s", "udp_fragment": False}
        self.update_inbound(out_json=json.dumps(template))
        row = self.snapshot()["inbounds"][0]
        self.assertTrue(row["available"])
        outbound = json.loads(row["outboundJson"])
        self.assertNotIn("transport", outbound)
        self.assertEqual(outbound["flow"], "xtls-rprx-vision")
        for field in ("connect_timeout", "tcp_fast_open", "tcp_multi_path", "tcp_keep_alive",
                      "tcp_keep_alive_interval", "udp_fragment"):
            self.assertEqual(outbound[field], template[field])
        template["tcp_fast_open"] = "true"
        self.update_inbound(out_json=json.dumps(template))
        self.assertFalse(self.snapshot()["inbounds"][0]["available"])

    def test_disabled_account_reads_status_but_receives_no_outbounds(self):
        self.update_client(enable=0)
        snapshot = self.snapshot()
        self.assertFalse(snapshot["enabled"])
        self.assertTrue(all(not row["available"] and row["outboundJson"] is None for row in snapshot["inbounds"]))

    def test_bytes_and_unlimited_zero_use_current_not_lifetime_counters(self):
        snapshot = self.snapshot()
        self.assertEqual((snapshot["uploadBytes"], snapshot["downloadBytes"], snapshot["trafficLimitBytes"]), (125, 250, 1000))
        self.update_client(volume=0, expiry=0)
        snapshot = self.snapshot()
        self.assertIsNone(snapshot["trafficLimitBytes"])
        self.assertIsNone(snapshot["expiresAt"])
        self.assertFalse(snapshot["activationPending"])

    def test_pending_activation_never_invents_expiry_or_unlimited_status(self):
        for expiry, delay in ((0, 1), (-86400, 0), (-86400, 1)):
            with self.subTest(expiry=expiry, delay=delay):
                self.update_client(expiry=expiry, delay_start=delay)
                snapshot = self.snapshot()
                self.assertTrue(snapshot["activationPending"])
                self.assertIsNone(snapshot["expiresAt"])
                self.assertTrue(snapshot["inbounds"][0]["available"])
        self.update_client(expiry=NOW + 60, delay_start=1)
        self.assertEqual(self.snapshot()["expiresAt"], NOW + 60)
        self.assertTrue(self.snapshot()["activationPending"])

    def test_expiry_and_quota_restrictions_match_upstream_strict_boundaries(self):
        self.update_client(volume=375, expiry=NOW)
        self.assertTrue(self.snapshot()["inbounds"][0]["available"])
        for fields in ({"volume": 374}, {"volume": 0, "expiry": NOW - 1}):
            self.update_client(**fields)
            snapshot = self.snapshot()
            self.assertTrue(snapshot["enabled"])
            self.assertTrue(all(row["outboundJson"] is None for row in snapshot["inbounds"]))

    def test_null_numbers_fail_closed_instead_of_becoming_false_unlimited(self):
        for field in ("volume", "expiry", "up", "down", "delay_start", "enable"):
            with self.subTest(field=field):
                with contextlib.closing(sqlite3.connect(self.path)) as db, db:
                    original = db.execute("SELECT " + field + " FROM clients WHERE id=1").fetchone()[0]
                self.update_client(**{field: None})
                with self.assertRaises(bridge.BridgeUnavailable):
                    self.snapshot()
                self.update_client(**{field: original})

    def test_invalid_or_null_assignment_never_grants_access(self):
        for assignment in (None, "null", '["1"]', '[{"id":1}]', '[true]', '[1,1]'):
            with self.subTest(assignment=assignment):
                self.update_client(inbounds=assignment)
                with self.assertRaises(bridge.BridgeUnavailable):
                    self.snapshot()
        self.update_client(inbounds="[]")
        self.assertTrue(all(row["outboundJson"] is None for row in self.snapshot()["inbounds"]))

    def test_unknown_uuid_noncanonical_uuid_and_duplicate_identity_are_unauthorized(self):
        for token in (UUID_A.upper(), "33333333-3333-4333-8333-333333333333", "{" + UUID_A + "}", UUID_A + " "):
            with self.subTest(token_shape=len(token)):
                with self.assertRaises(bridge.Unauthorized):
                    self.store.snapshot(token, now=NOW)
        with contextlib.closing(sqlite3.connect(self.path)) as db, db:
            own = db.execute("SELECT config FROM clients WHERE id=1").fetchone()[0]
            db.execute("UPDATE clients SET config=? WHERE id=2", (own,))
        with self.assertRaises(bridge.Unauthorized):
            self.snapshot()

    def test_address_override_is_finalized_before_validation_and_tag_is_stable(self):
        self.update_inbound(addrs=json.dumps([
            {"server": "edge.example.test", "server_port": 8443, "remark": "ignored display suffix",
             "tls": {"server_name": "edge.example.test"}},
            {"server": "second.example.test", "server_port": 9443}]))
        outbound = json.loads(self.snapshot()["inbounds"][0]["outboundJson"])
        self.assertEqual((outbound["server"], outbound["server_port"]), ("edge.example.test", 8443))
        self.assertEqual(outbound["tls"]["server_name"], "edge.example.test")
        self.assertEqual(outbound["tag"], "stable-1")

    def test_public_certificate_and_valid_reality_survive_but_no_key_is_repaired(self):
        template = {"type": "vless", "tag": "stable-1", "server": "vpn.example.test", "server_port": 443,
                    "tls": {"enabled": True, "server_name": "vpn.example.test",
                            "certificate": ["-----BEGIN CERTIFICATE-----\nsynthetic-public\n-----END CERTIFICATE-----"],
                            "utls": {"enabled": True, "fingerprint": "chrome"},
                            "reality": {"enabled": True, "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "short_id": "ab12"}}}
        self.update_inbound(out_json=json.dumps(template))
        row = self.snapshot()["inbounds"][0]
        self.assertTrue(row["available"])
        self.assertEqual(json.loads(row["outboundJson"])["tls"], template["tls"])
        for bad in ("", "not-a-reality-key", "A" * 42 + "B"):
            template["tls"]["reality"]["public_key"] = bad
            self.update_inbound(out_json=json.dumps(template))
            row = self.snapshot()["inbounds"][0]
            self.assertFalse(row["available"])
            self.assertIsNone(row["outboundJson"])

    def test_server_keys_user_arrays_paths_insecure_and_unknown_fields_are_not_exported(self):
        base = {"type": "vless", "tag": "stable-1", "server": "vpn.example.test", "server_port": 443,
                "tls": {"enabled": True}}
        for mutate in (
            lambda t: t["tls"].update(key=["SENSITIVE-PRIVATE-KEY"]),
            lambda t: t["tls"].update(certificate_path="/sensitive/file"),
            lambda t: t["tls"].update(insecure=True),
            lambda t: t.update(users=[{"uuid": UUID_B}]),
            lambda t: t.update(detour="other-account"),
            lambda t: t.update(password="OTHER-ACCOUNT-PASSWORD"),
            lambda t: t.update(unknown="OTHER-ACCOUNT-PASSWORD"),
        ):
            template = json.loads(json.dumps(base))
            mutate(template)
            self.update_inbound(out_json=json.dumps(template))
            row = self.snapshot()["inbounds"][0]
            self.assertFalse(row["available"])
            self.assertIsNone(row["outboundJson"])

    def test_flow_is_removed_for_non_tcp_transport(self):
        template = {"type": "vless", "tag": "stable-1", "server": "vpn.example.test", "server_port": 443,
                    "tls": {"enabled": True}, "transport": {"type": "ws", "path": "/vpn", "headers": {"Host": "vpn.example.test"}}}
        self.update_inbound(out_json=json.dumps(template))
        self.assertNotIn("flow", json.loads(self.snapshot()["inbounds"][0]["outboundJson"]))

    def test_missing_protocol_credentials_make_only_that_inbound_unavailable(self):
        with contextlib.closing(sqlite3.connect(self.path)) as db, db:
            config = json.loads(db.execute("SELECT config FROM clients WHERE id=1").fetchone()[0])
        del config["tuic"]["password"]
        self.update_client(config=json.dumps(config))
        rows = self.snapshot()["inbounds"]
        self.assertTrue(rows[0]["available"])
        self.assertFalse(rows[9]["available"])
        self.assertIsNone(rows[9]["outboundJson"])

    def test_quic_public_certificate_accepts_panel_line_split_pem(self):
        certificate = ["-----BEGIN CERTIFICATE-----", "c3ludGhldGljLXB1YmxpYw==", "-----END CERTIFICATE-----", ""]
        for ident, protocol in ((10, "tuic"), (12, "hysteria2")):
            with self.subTest(protocol=protocol):
                template = {"type": protocol, "tag": "stable-" + str(ident),
                            "server": "vpn.example.test", "server_port": 443,
                            "tls": {"enabled": True, "certificate": certificate, "alpn": ["h3"]}}
                self.update_inbound(ident=ident, out_json=json.dumps(template))
                row = self.snapshot()["inbounds"][ident - 1]
                self.assertTrue(row["available"])
                self.assertEqual(json.loads(row["outboundJson"])["tls"]["certificate"], certificate)

    def test_internal_reality_projection_keeps_tls_identity_key_and_stable_tag(self):
        tls = {"enabled": True, "server_name": "reality-cover.example.test",
               "utls": {"enabled": True, "fingerprint": "chrome"},
               "reality": {"enabled": True, "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                           "short_id": "ab12"}}
        template = {"type": "vless", "tag": "stable-1", "server": "127.0.0.1",
                    "server_port": 4443, "tls": tls}
        self.update_inbound(out_json=json.dumps(template))
        store = bridge.AccountStore(self.path, public_host="edge.example.test", port_maps={1: (4443, 443)})
        row = store.snapshot(UUID_A, now=NOW)["inbounds"][0]
        self.assertTrue(row["available"])
        outbound = json.loads(row["outboundJson"])
        self.assertEqual((outbound["server"], outbound["server_port"]), ("edge.example.test", 443))
        self.assertEqual(outbound["tls"], tls)
        self.assertEqual((outbound["tag"], outbound["uuid"]), ("stable-1", UUID_A))


    def test_missing_public_host_and_stale_internal_port_mapping_make_option_unavailable(self):
        for server in ("127.0.0.1", "127.0.0.2", "::1", "::ffff:127.0.0.1", "localhost", "LOCALHOST."):
            with self.subTest(server=server):
                template = {"type": "vless", "tag": "stable-1", "server": server,
                            "server_port": 4443, "tls": {"enabled": True}}
                self.update_inbound(out_json=json.dumps(template))
                self.assertFalse(self.snapshot()["inbounds"][0]["available"])
                store = bridge.AccountStore(self.path, public_host="edge.example.test", port_maps={1: (9999, 443)})
                row = store.snapshot(UUID_A, now=NOW)["inbounds"][0]
                self.assertFalse(row["available"])
                self.assertIsNone(row["outboundJson"])

    def test_explicit_public_address_override_is_never_overwritten_by_projection_or_port_map(self):
        template = {"type": "vless", "tag": "stable-1", "server": "127.0.0.1",
                    "server_port": 4443, "tls": {"enabled": True, "server_name": "original.example.test"}}
        self.update_inbound(out_json=json.dumps(template), addrs=json.dumps([
            {"server": "explicit.example.test", "server_port": 8443,
             "tls": {"server_name": "explicit-sni.example.test"}}]))
        store = bridge.AccountStore(self.path, public_host="edge.example.test", port_maps={1: (9999, 443)})
        row = store.snapshot(UUID_A, now=NOW)["inbounds"][0]
        self.assertTrue(row["available"])
        outbound = json.loads(row["outboundJson"])
        self.assertEqual((outbound["server"], outbound["server_port"]), ("explicit.example.test", 8443))
        self.assertEqual(outbound["tls"]["server_name"], "explicit-sni.example.test")

    def test_loopback_address_override_is_projected_after_its_port_and_tls_merge(self):
        self.update_inbound(addrs=json.dumps([{"server": "::1", "server_port": 4443,
                                               "tls": {"server_name": "merged.example.test"}}]))
        store = bridge.AccountStore(self.path, public_host="edge.example.test", port_maps={1: (4443, 443)})
        outbound = json.loads(store.snapshot(UUID_A, now=NOW)["inbounds"][0]["outboundJson"])
        self.assertEqual((outbound["server"], outbound["server_port"]), ("edge.example.test", 443))
        self.assertEqual(outbound["tls"]["server_name"], "merged.example.test")

    def test_projection_configuration_rejects_unsafe_hosts_and_port_maps(self):
        for host in ("localhost", "127.0.0.1", "::1", "10.0.0.1", "192.168.1.1", "0.0.0.0",
                     "224.0.0.1", "https://edge.example.test", "user@edge.example.test",
                     "edge.example.test:443", "edge.example.test/path", "*.example.test", "edge\\n.example.test"):
            with self.subTest(kind="host"):
                with self.assertRaises(ValueError):
                    bridge.AccountStore(self.path, public_host=host)
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
                    bridge.main(["--public-host", host])
                self.assertEqual(caught.exception.code, 2)
        for mapping in ("1:0:443", "0:4443:443", "1:4443:65536", "1:4443", "1:4443:443:80", "x:4443:443", "-1:4443:443"):
            with self.subTest(kind="map"):
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
                    bridge.main(["--port-map=" + mapping])
                self.assertEqual(caught.exception.code, 2)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            bridge.main(["--port-map", "1:4443:443", "--port-map", "1:4443:8443"])
        self.assertEqual(caught.exception.code, 2)
        for mapping in ({True: (4443, 443)}, {1: (4443, False)}, {1: (4443,)}, {1: "4443:443"}):
            with self.assertRaises(ValueError):
                bridge.AccountStore(self.path, public_host="edge.example.test", port_maps=mapping)

    def test_projection_arguments_reach_store_without_widening_http_bind(self):
        with bridge.BridgeServer(self.path, port=0, public_host="8.8.8.8", port_maps={1: (4443, 443)}) as server:
            self.assertEqual(server.server_address[0], "127.0.0.1")
            self.assertEqual(server.store.public_host, "8.8.8.8")
            self.assertEqual(server.store.port_maps, {1: (4443, 443)})

    def test_quic_disabled_tcp_placeholders_are_removed_but_enabled_or_secret_fields_fail(self):
        template = {"type": "tuic", "tag": "stable-10", "server": "vpn.example.test", "server_port": 443,
                    "tls": {"enabled": True, "utls": {"enabled": False}, "reality": {"enabled": False}}}
        self.update_inbound(ident=10, out_json=json.dumps(template))
        row = self.snapshot()["inbounds"][9]
        self.assertTrue(row["available"])
        self.assertEqual(json.loads(row["outboundJson"])["tls"], {"enabled": True})
        for extra in ({"utls": {"enabled": True, "fingerprint": "chrome"}},
                      {"reality": {"enabled": False, "private_key": "NO-EXPORT"}},
                      {"insecure": True}):
            template["tls"] = {"enabled": True, **extra}
            self.update_inbound(ident=10, out_json=json.dumps(template))
            self.assertFalse(self.snapshot()["inbounds"][9]["available"])

    def test_oversized_address_json_is_not_treated_as_missing_and_fallback_is_forbidden(self):
        self.update_inbound(addrs=" " * (32 * 1024 + 1))
        row = self.snapshot()["inbounds"][0]
        self.assertFalse(row["available"])
        self.assertIsNone(row["outboundJson"])

    def test_non_ascii_uuid_and_nil_uuid_are_not_accepted(self):
        for token in ("１１１１１１１１-1111-4111-8111-11111111111a", "00000000-0000-0000-0000-000000000000"):
            with self.assertRaises(bridge.Unauthorized):
                self.store.snapshot(token, now=NOW)

    def test_database_is_read_only_and_missing_database_is_not_created(self):
        with contextlib.closing(self.store.connect()) as db:
            with self.assertRaises(sqlite3.OperationalError):
                db.execute("UPDATE clients SET enable=0")
        missing = Path(self.temp.name) / "missing.db"
        with self.assertRaises(bridge.BridgeUnavailable):
            bridge.AccountStore(missing).snapshot(UUID_A, now=NOW)
        self.assertFalse(missing.exists())

    def test_duplicate_json_and_unsupported_protocol_fail_closed(self):
        self.update_inbound(out_json='{"type":"vless","type":"tuic"}')
        self.assertFalse(self.snapshot()["inbounds"][0]["available"])
        self.update_inbound(type="unsupported")
        row = self.snapshot()["inbounds"][0]
        self.assertEqual(row["protocol"], "unsupported")
        self.assertIsNone(row["outboundJson"])

    def test_response_size_and_catalog_count_are_capped(self):
        with self.assertRaises(bridge.BridgeUnavailable):
            bridge.encode_snapshot({"large": "x" * (512 * 1024)})
        with contextlib.closing(sqlite3.connect(self.path)) as db, db:
            for ident in range(13, 130):
                db.execute("INSERT INTO inbounds VALUES (?,?,?,?,?,?,?)", (ident, "vless", "extra", 1, "[]", "{}", "{}"))
        with self.assertRaises(bridge.BridgeUnavailable):
            self.snapshot()


class HttpTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "s-ui.db"
        fixture_database(self.path)
        self.server = bridge.BridgeServer(self.path, port=0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def request(self, extra=b"", method=b"GET", path=b"/v1/account", auth=None):
        token = UUID_A.encode("ascii") if auth is None else auth
        request = method + b" " + path + b" HTTP/1.1\r\nHost: 127.0.0.1:" + str(self.server.server_address[1]).encode() + b"\r\n"
        if token:
            request += b"Authorization: Bearer " + token + b"\r\n"
        return self.raw_request(request + extra + b"\r\n")

    def raw_request(self, request):
        with socket.create_connection(self.server.server_address, timeout=3) as conn:
            conn.settimeout(3)
            conn.sendall(request)
            chunks = []
            while True:
                try:
                    chunk = conn.recv(65536)
                except ConnectionResetError:
                    if chunks:
                        break
                    raise
                if not chunk:
                    break
                chunks.append(chunk)
        head, _, body = b"".join(chunks).partition(b"\r\n\r\n")
        return int(head.split(b" ")[1]), head, body

    def test_loopback_success_has_no_store_no_cors_and_no_credentials_in_logs(self):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
            code, headers, body = self.request()
            self.assertEqual(code, 200)
            self.assertEqual(len(json.loads(body)["inbounds"]), 12)
            self.assertEqual(self.request(auth=b"not-a-uuid")[0], 401)
        self.assertIn(b"Cache-Control: no-store", headers)
        self.assertNotIn(b"Access-Control-Allow-Origin", headers)
        self.assertEqual(stream.getvalue(), "")
        self.assertEqual(self.server.server_address[0], "127.0.0.1")

    def test_missing_unknown_malformed_and_duplicate_auth_have_same_401(self):
        responses = [self.request(auth=b""), self.request(auth=UUID_B.replace("2", "3").encode()),
                     self.request(auth=b"not-a-uuid"),
                     self.request(extra=b"Authorization: Bearer " + UUID_B.encode() + b"\r\n")]
        self.assertTrue(all(item[0] == 401 for item in responses))
        self.assertEqual(len({item[2] for item in responses}), 1)
        self.assertTrue(all(UUID_A.encode() not in item[2] and UUID_B.encode() not in item[2] for item in responses))

    def test_query_tokens_bodies_browser_origins_and_non_get_are_rejected(self):
        for args in ({"path": b"/v1/account?token=" + UUID_A.encode()},
                     {"extra": b"Content-Length: 1\r\n"},
                     {"extra": b"Transfer-Encoding: chunked\r\n"},
                     {"extra": b"Origin: https://example.test\r\n"},
                     {"method": b"POST"}, {"method": b"HEAD"}, {"method": b"OPTIONS"}):
            with self.subTest(kind=list(args)):
                self.assertNotEqual(self.request(**args)[0], 200)

    def test_header_limit_folding_and_host_rebinding_are_rejected(self):
        for extra in (b"X-Large: " + b"x" * 9000 + b"\r\n", b" folded: invalid\r\n",
                      b"Host: attacker.example\r\n", b"X: a\r\n" * 40):
            with self.subTest(length=len(extra)):
                self.assertNotEqual(self.request(extra=extra)[0], 200)

    def test_global_request_rate_is_bounded_without_identity_storage(self):
        codes = [self.request(auth=b"unknown")[0] for _ in range(30)]
        self.assertIn(429, codes)

    def test_concurrent_slow_headers_cannot_create_unbounded_workers(self):
        active = 0
        lock = threading.Lock()
        full = threading.Event()

        class ObservedServer(bridge.BridgeServer):
            def process_request_thread(server, request, address):
                nonlocal active
                with lock:
                    active += 1
                    if active == 8:
                        full.set()
                try:
                    super().process_request_thread(request, address)
                finally:
                    with lock:
                        active -= 1

        with ObservedServer(self.path, port=0) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with contextlib.ExitStack() as clients:
                    for _ in range(8):
                        client = clients.enter_context(socket.create_connection(server.server_address, timeout=3))
                        client.sendall(b"GET /v1/account HTTP/1.1\r\n")
                    self.assertTrue(full.wait(timeout=3))
                    with socket.create_connection(server.server_address, timeout=3) as extra:
                        extra.settimeout(3)
                        self.assertEqual(extra.recv(1), b"")
                    with lock:
                        self.assertEqual(active, 8)
            finally:
                server.shutdown()
                thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
