use anyhow::{Result, anyhow, bail, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::{Client, header::{AUTHORIZATION, HeaderValue}};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, net::IpAddr, time::{Duration, SystemTime, UNIX_EPOCH}};
use tokio_util::sync::CancellationToken;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use crate::{models::ProxyEndpoint, preferences::FINGERPRINTS, profile::parse_strict};

pub const BRIDGE_URL: &str = "http://127.0.0.1:2099/v1/account";
const MAX_RESPONSE: usize = 512 * 1024;
const MAX_TEMPLATE: usize = 64 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountSnapshot {
    pub format: i32,
    pub generated_at: i64,
    pub subject: String,
    pub enabled: bool,
    #[serde(deserialize_with = "required_option")]
    pub expires_at: Option<i64>,
    pub activation_pending: bool,
    #[serde(deserialize_with = "required_option")]
    pub traffic_limit_bytes: Option<u64>,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub inbounds: Vec<InboundOption>,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InboundOption {
    pub id: u64,
    pub label: String,
    pub protocol: String,
    pub available: bool,
    pub unavailable_reason: String,
    #[serde(deserialize_with = "required_option")]
    pub outbound_json: Option<String>,
}

// Explicit nullable fields are part of the wire schema, not optional properties.
fn required_option<'de, D, T>(deserializer: D) -> std::result::Result<Option<T>, D::Error>
where D: Deserializer<'de>, T: Deserialize<'de> { Option::deserialize(deserializer) }

#[derive(Clone)]
pub struct AccountClient { client: Client }
impl AccountClient {
    pub fn new(proxy: &ProxyEndpoint) -> Result<Self> {
        ensure!(proxy.port != 0 && !proxy.username.is_empty() && !proxy.password.is_empty()
            && proxy.username.len() <= 255 && proxy.password.len() <= 255,
            "Invalid authenticated account proxy");
        let proxy = reqwest::Proxy::all(format!("socks5h://127.0.0.1:{}", proxy.port))
            .map_err(|_| anyhow!("Invalid account proxy configuration"))?
            .basic_auth(&proxy.username, &proxy.password);
        let client = Client::builder().no_proxy().proxy(proxy)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(8)).timeout(REQUEST_TIMEOUT)
            .pool_max_idle_per_host(1).pool_idle_timeout(Duration::from_secs(60))
            .no_gzip().no_brotli().no_deflate().no_zstd()
            .build().map_err(|_| anyhow!("Cannot initialize private account transport"))?;
        Ok(Self { client })
    }

    pub async fn fetch(&self, uuid: &str, cancel: &CancellationToken) -> Result<AccountSnapshot> {
        canonical_uuid(uuid)?;
        ensure!(!cancel.is_cancelled(), "Account request cancelled");
        // HeaderValue's sensitive flag also prevents accidental HTTP debug disclosure.
        let bearer = Zeroizing::new(format!("Bearer {uuid}"));
        let mut authorization = HeaderValue::from_str(&bearer)
            .map_err(|_| anyhow!("Invalid account authentication"))?;
        authorization.set_sensitive(true);
        let operation = async {
            let mut response = self.client.get(BRIDGE_URL)
                .header(AUTHORIZATION, authorization).header("Accept", "application/json")
                .send().await.map_err(|_| anyhow!("Private account service unavailable through VPN; no other route was used"))?;
            ensure!(response.status().as_u16() == 200, "Private account service returned HTTP {}", response.status().as_u16());
            ensure!(response.content_length().is_none_or(|size| size <= MAX_RESPONSE as u64), "Account response exceeds size limit");
            let mut bytes = Zeroizing::new(Vec::new());
            while let Some(chunk) = response.chunk().await.map_err(|_| anyhow!("Private account response interrupted"))? {
                ensure!(chunk.len() <= MAX_RESPONSE.saturating_sub(bytes.len()), "Account response exceeds size limit");
                bytes.extend_from_slice(&chunk);
            }
            let snapshot: AccountSnapshot = parse_strict(&bytes, MAX_RESPONSE)
                .map_err(|_| anyhow!("Invalid private account response schema"))?;
            validate(&snapshot, uuid)?;
            let now = SystemTime::now().duration_since(UNIX_EPOCH)
                .map_err(|_| anyhow!("System clock cannot validate account response"))?.as_secs();
            validate_freshness(snapshot.generated_at, now)?;
            Ok(snapshot)
        };
        tokio::select! {
            biased;
            _ = cancel.cancelled() => bail!("Account request cancelled"),
            result = tokio::time::timeout(REQUEST_TIMEOUT, operation) =>
                result.map_err(|_| anyhow!("Private account request timed out"))?,
        }
    }
}

fn canonical_uuid(text: &str) -> Result<()> {
    let uuid = uuid::Uuid::parse_str(text).map_err(|_| anyhow!("Invalid canonical account UUID"))?;
    let mut canonical = [0u8; 36];
    ensure!(!uuid.is_nil() && uuid.hyphenated().encode_lower(&mut canonical).as_bytes() == text.as_bytes(),
        "Invalid canonical account UUID");
    Ok(())
}

// Cached snapshots remain useful offline; only fetch applies the five-minute window.
pub fn validate(snapshot: &AccountSnapshot, uuid: &str) -> Result<()> {
    canonical_uuid(uuid)?;
    ensure!(snapshot.format == 1, "Unsupported account response format");
    ensure!(snapshot.generated_at > 0, "Invalid account generation timestamp");
    let digest = Sha256::digest(uuid.as_bytes());
    const HEX: &[u8; 16] = b"0123456789abcdef";
    ensure!(snapshot.subject.len() == 64 && snapshot.subject.bytes().enumerate().all(|(index, byte)|
        byte == HEX[if index % 2 == 0 { digest[index / 2] >> 4 } else { digest[index / 2] & 15 } as usize]),
        "Account response belongs to another identity");
    ensure!(snapshot.expires_at.is_none_or(|value| value > 0), "Invalid account expiry");
    ensure!(snapshot.traffic_limit_bytes.is_none_or(|value| value > 0), "Invalid account traffic limit");
    ensure!(snapshot.inbounds.len() <= 128, "Too many account connection options");
    let mut ids = HashSet::with_capacity(snapshot.inbounds.len());
    let mut size = 0usize;
    for inbound in &snapshot.inbounds {
        ensure!(ids.insert(inbound.id), "Duplicate account connection option ID");
        ensure!(snapshot.enabled || !inbound.available, "Disabled account contains an available connection option");
        validate_inbound(inbound)?;
        size += inbound.label.len() + inbound.protocol.len() + inbound.unavailable_reason.len()
            + inbound.outbound_json.as_ref().map_or(0, String::len);
        ensure!(size <= MAX_RESPONSE, "Account connection catalog exceeds size limit");
    }
    Ok(())
}

fn validate_freshness(generated_at: i64, now: u64) -> Result<()> {
    ensure!(generated_at > 0 && (generated_at as u64).abs_diff(now) <= 300,
        "Private account response is stale or has a future timestamp");
    Ok(())
}

pub fn validate_inbound(inbound: &InboundOption) -> Result<()> {
    ensure!(inbound.id > 0, "Invalid account connection option ID");
    bounded_text(&inbound.label, 256, false, "Invalid account connection label")?;
    bounded_text(&inbound.protocol, 32, false, "Invalid account connection protocol")?;
    bounded_text(&inbound.unavailable_reason, 512, true, "Invalid account connection availability reason")?;
    if !inbound.available {
        ensure!(inbound.outbound_json.is_none() && !inbound.unavailable_reason.is_empty(), "Unavailable connection option must not contain a client template");
        return Ok(());
    }
    ensure!(inbound.unavailable_reason.is_empty(), "Available connection option has an unavailability reason");
    ensure!(matches!(inbound.protocol.as_str(), "vless" | "vmess" | "tuic" | "hysteria2"), "Unsupported available connection protocol");
    let text = inbound.outbound_json.as_deref().ok_or_else(|| anyhow!("Available connection option lacks a client template"))?;
    let value = SecretValue(parse_strict(text.as_bytes(), MAX_TEMPLATE)
        .map_err(|_| anyhow!("Invalid connection template JSON, duplicate field, or size limit"))?);
    validate_template(&value.0, &inbound.protocol)
}

// Value is used only within this validator; erase parsed credentials on every exit.
struct SecretValue(Value);
impl Drop for SecretValue {
    fn drop(&mut self) {
        fn erase(value: &mut Value) {
            match value {
                Value::String(text) => text.zeroize(),
                Value::Array(values) => values.iter_mut().for_each(erase),
                Value::Object(map) => for (mut key, mut value) in std::mem::take(map) { key.zeroize(); erase(&mut value); },
                _ => (),
            }
        }
        erase(&mut self.0);
    }
}

type Object = Map<String, Value>;
fn object(value: &Value) -> Result<&Object> { value.as_object().ok_or_else(|| anyhow!("Connection template requires an object")) }
fn fields(map: &Object, allowed: &[&str]) -> Result<()> {
    // Never echo a response-supplied field name or value: either can contain a secret.
    ensure!(!map.keys().any(|key| ["certificate_path", "key_path", "client_certificate_path", "client_key_path", "config_path"].contains(&key.as_str())),
        "Connection template file references are forbidden");
    ensure!(!map.keys().any(|key| ["key", "private_key", "client_key", "users"].contains(&key.as_str())),
        "Connection template contains server users or private TLS keys");
    ensure!(!map.keys().any(|key| ["action", "execute", "command", "commands", "script", "exec"].contains(&key.as_str())),
        "Connection template actions and executable commands are forbidden");
    ensure!(map.keys().all(|key| allowed.contains(&key.as_str())), "Connection template contains a forbidden or unsupported field");
    Ok(())
}
fn bounded_text(text: &str, max: usize, empty: bool, error: &'static str) -> Result<()> {
    ensure!((empty || !text.trim().is_empty()) && text.len() <= max && !text.chars().any(char::is_control), "{error}");
    Ok(())
}
fn string<'a>(map: &'a Object, key: &str, max: usize, required: bool) -> Result<Option<&'a str>> {
    match map.get(key) {
        None if !required => Ok(None),
        Some(Value::String(text)) => { bounded_text(text, max, !required, "Invalid connection template string")?; Ok(Some(text)) }
        _ => bail!("Missing or invalid connection template string"),
    }
}
fn boolean(map: &Object, key: &str) -> Result<()> {
    ensure!(map.get(key).is_none_or(Value::is_boolean), "Invalid connection template boolean"); Ok(())
}
fn integer(map: &Object, key: &str, max: u64, required: bool) -> Result<()> {
    match map.get(key) {
        None if !required => Ok(()),
        Some(value) if value.as_u64().is_some_and(|number| number <= max && (!required || number > 0)) => Ok(()),
        _ => bail!("Invalid connection template numeric field"),
    }
}
fn choice(map: &Object, key: &str, choices: &[&str]) -> Result<()> {
    if let Some(text) = string(map, key, 128, false)? { ensure!(choices.contains(&text), "Unsupported connection template option"); }
    Ok(())
}
fn string_list(value: &Value, max_items: usize, max_text: usize, multiline: bool) -> Result<()> {
    let check = |value: &Value| -> Result<()> {
        let text = value.as_str().ok_or_else(|| anyhow!("Invalid connection template string list"))?;
        ensure!(text.len() <= max_text && !text.chars().any(|c| c.is_control() && !(multiline && matches!(c, '\r' | '\n'))), "Invalid connection template string list");
        if multiline { ensure!(!text.contains("PRIVATE KEY"), "TLS private keys are forbidden in connection templates"); }
        Ok(())
    };
    if let Some(values) = value.as_array() {
        ensure!(values.len() <= max_items, "Connection template string list exceeds size limit");
        for value in values { check(value)?; }
    } else { check(value)?; }
    Ok(())
}
fn duration(map: &Object, key: &str) -> Result<()> {
    if let Some(text) = string(map, key, 32, false)? {
        let mut remaining = text;
        if remaining == "0" { return Ok(()); }
        while !remaining.is_empty() {
            let number_len = remaining.bytes().take_while(|byte| byte.is_ascii_digit() || *byte == b'.').count();
            let number = &remaining[..number_len];
            ensure!(number.bytes().any(|byte| byte.is_ascii_digit()) && number.bytes().filter(|byte| *byte == b'.').count() <= 1,
                "Invalid connection template duration");
            remaining = &remaining[number_len..];
            let unit = ["ns", "us", "µs", "μs", "ms", "s", "m", "h"].into_iter()
                .find(|unit| remaining.starts_with(*unit)).ok_or_else(|| anyhow!("Invalid connection template duration"))?;
            remaining = &remaining[unit.len()..];
        }
        ensure!(!text.is_empty(), "Invalid connection template duration");
    }
    Ok(())
}
fn host(text: &str) -> bool {
    text.parse::<IpAddr>().is_ok() || (text.len() <= 253 && !text.is_empty() && text.split('.').all(|label|
        !label.is_empty() && label.len() <= 63 && !label.starts_with('-') && !label.ends_with('-')
            && label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')))
}

fn validate_template(value: &Value, protocol: &str) -> Result<()> {
    let map = object(value)?;
    // These are client-only subsets of official sing-box v1.15.0-alpha.13 option
    // structs. Dialer detours, local paths, user arrays and executable hooks are absent.
    let allowed: &[&str] = match protocol {
        "vless" => &["type", "tag", "server", "server_port", "uuid", "flow", "network", "tls", "packet_encoding", "transport", "multiplex", "connect_timeout", "tcp_fast_open", "tcp_multi_path", "tcp_keep_alive", "tcp_keep_alive_interval", "udp_fragment"],
        "vmess" => &["type", "tag", "server", "server_port", "uuid", "security", "alter_id", "global_padding", "authenticated_length", "network", "tls", "packet_encoding", "transport", "multiplex", "connect_timeout", "tcp_fast_open", "tcp_multi_path", "tcp_keep_alive", "tcp_keep_alive_interval", "udp_fragment"],
        "tuic" => &["type", "tag", "server", "server_port", "uuid", "password", "congestion_control", "udp_relay_mode", "udp_over_stream", "zero_rtt_handshake", "heartbeat", "network", "tls", "connect_timeout", "tcp_fast_open", "tcp_multi_path", "tcp_keep_alive", "tcp_keep_alive_interval", "udp_fragment"],
        "hysteria2" => &["type", "tag", "server", "server_port", "server_ports", "hop_interval", "hop_interval_max", "up_mbps", "down_mbps", "obfs", "password", "network", "tls", "bbr_profile", "disable_chrome_parrot", "connect_timeout", "tcp_fast_open", "tcp_multi_path", "tcp_keep_alive", "tcp_keep_alive_interval", "udp_fragment"],
        _ => bail!("Unsupported connection template protocol"),
    };
    fields(map, allowed)?;
    for key in ["connect_timeout", "tcp_keep_alive", "tcp_keep_alive_interval"] { duration(map, key)?; }
    for key in ["tcp_fast_open", "tcp_multi_path", "udp_fragment"] { boolean(map, key)?; }
    if let Some(tag) = string(map, "tag", 128, false)? {
        ensure!(!tag.is_empty() && tag.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte)),
            "Unsafe connection template tag");
    }
    ensure!(string(map, "type", 32, true)? == Some(protocol), "Connection template protocol mismatch");
    ensure!(host(string(map, "server", 253, true)?.unwrap_or("")), "Invalid connection server address");
    integer(map, "server_port", u16::MAX as u64, true)?;
    choice(map, "network", &["", "tcp", "udp", "tcp,udp", "udp,tcp"])?;
    if protocol != "hysteria2" { canonical_uuid(string(map, "uuid", 36, true)?.unwrap_or(""))?; }
    if matches!(protocol, "tuic" | "hysteria2") { string(map, "password", 1024, true)?; }
    if protocol == "vless" { choice(map, "flow", &["", "xtls-rprx-vision"])?; }
    if matches!(protocol, "vless" | "vmess") {
        choice(map, "packet_encoding", &["", "packetaddr", "xudp"])?;
        if let Some(transport) = map.get("transport") { validate_transport(transport)?; }
        if let Some(multiplex) = map.get("multiplex") { validate_multiplex(multiplex)?; }
    }
    if protocol == "vmess" {
        choice(map, "security", &["", "auto", "none", "zero", "aes-128-cfb", "aes-128-gcm", "chacha20-poly1305"])?;
        integer(map, "alter_id", u16::MAX as u64, false)?;
        boolean(map, "global_padding")?; boolean(map, "authenticated_length")?;
    }
    if protocol == "tuic" {
        choice(map, "congestion_control", &["", "cubic", "new_reno", "bbr"])?;
        choice(map, "udp_relay_mode", &["", "native", "quic"])?;
        boolean(map, "udp_over_stream")?; boolean(map, "zero_rtt_handshake")?; duration(map, "heartbeat")?;
    }
    if protocol == "hysteria2" {
        integer(map, "up_mbps", u32::MAX as u64, false)?; integer(map, "down_mbps", u32::MAX as u64, false)?;
        choice(map, "bbr_profile", &["", "standard", "conservative", "aggressive"])?;
        boolean(map, "disable_chrome_parrot")?; duration(map, "hop_interval")?; duration(map, "hop_interval_max")?;
        if let Some(ports) = map.get("server_ports") {
            string_list(ports, 32, 32, false)?;
            let check = |text: &str| -> bool { !text.is_empty() && text.split(':').count() <= 2
                && text.split(':').all(|port| port.parse::<u16>().is_ok_and(|port| port > 0)) };
            ensure!(match ports { Value::String(text) => check(text), Value::Array(values) => values.iter().all(|value| value.as_str().is_some_and(check)), _ => false }, "Invalid connection server port range");
        }
        if let Some(obfs) = map.get("obfs") {
            let obfs = object(obfs)?; fields(obfs, &["type", "password", "min_packet_size", "max_packet_size"])?;
            choice(obfs, "type", &["salamander", "gecko"])?;
            let kind = string(obfs, "type", 32, true)?.unwrap_or("");
            string(obfs, "password", 1024, true)?;
            if kind == "salamander" { ensure!(!obfs.contains_key("min_packet_size") && !obfs.contains_key("max_packet_size"), "Unsupported obfuscation options"); }
            integer(obfs, "min_packet_size", u16::MAX as u64, false)?; integer(obfs, "max_packet_size", u16::MAX as u64, false)?;
        }
    }
    let quic = matches!(protocol, "tuic" | "hysteria2") || map.get("transport").and_then(|v| v.get("type")).and_then(Value::as_str) == Some("quic");
    if let Some(tls) = map.get("tls") { validate_tls(tls, quic)?; }
    else { ensure!(!quic, "QUIC connection template requires TLS"); }
    Ok(())
}

fn validate_tls(value: &Value, quic: bool) -> Result<()> {
    let map = object(value)?;
    fields(map, &["enabled", "engine", "disable_sni", "server_name", "insecure", "alpn", "min_version", "max_version", "cipher_suites", "curve_preferences", "certificate", "certificate_sha256", "certificate_public_key_sha256", "fragment", "fragment_fallback_delay", "record_fragment", "handshake_timeout", "utls", "reality", "ech"])?;
    for key in ["enabled", "disable_sni", "insecure", "fragment", "record_fragment"] { boolean(map, key)?; }
    ensure!(map.get("insecure").is_none_or(|value| value.as_bool() == Some(false)), "Insecure TLS is forbidden in connection templates");
    if quic { ensure!(map.get("enabled").and_then(Value::as_bool) == Some(true), "QUIC connection template requires enabled TLS"); }
    if let Some(name) = string(map, "server_name", 253, false)? { ensure!(name.is_empty() || host(name), "Invalid TLS server name"); }
    choice(map, "engine", &["", "go", "windows", "apple"])?;
    for key in ["min_version", "max_version"] { choice(map, key, &["", "1.0", "1.1", "1.2", "1.3"])?; }
    for key in ["alpn", "cipher_suites", "curve_preferences", "certificate_sha256", "certificate_public_key_sha256"] {
        if let Some(value) = map.get(key) { string_list(value, 32, 256, false)?; }
    }
    if let Some(value) = map.get("certificate") { string_list(value, 256, 32 * 1024, true)?; }
    duration(map, "fragment_fallback_delay")?; duration(map, "handshake_timeout")?;
    if let Some(value) = map.get("utls") {
        ensure!(!quic, "QUIC connection template must not use uTLS");
        let utls = object(value)?; fields(utls, &["enabled", "fingerprint"])?; boolean(utls, "enabled")?;
        if let Some(fingerprint) = string(utls, "fingerprint", 32, false)? {
            ensure!(fingerprint.is_empty() || FINGERPRINTS.contains(&fingerprint), "Unsupported TLS fingerprint in connection template");
        }
    }
    if let Some(value) = map.get("reality") {
        ensure!(!quic, "QUIC connection template must not use REALITY");
        let reality = object(value)?; fields(reality, &["enabled", "public_key", "short_id"])?; boolean(reality, "enabled")?;
        let key = string(reality, "public_key", 64, true)?.unwrap_or("");
        let mut decoded = [0u8; 33];
        ensure!(key.len() == 43 && URL_SAFE_NO_PAD.decode_slice(key, &mut decoded).is_ok_and(|size| size == 32),
            "Invalid REALITY public key");
        let id = string(reality, "short_id", 16, false)?.unwrap_or("");
        ensure!(id.len() % 2 == 0 && id.bytes().all(|byte| byte.is_ascii_hexdigit()), "Invalid REALITY short ID");
        if reality.get("enabled").and_then(Value::as_bool) == Some(true) {
            ensure!(map.get("enabled").and_then(Value::as_bool) == Some(true)
                && map.get("utls").and_then(|value| value.get("enabled")).and_then(Value::as_bool) == Some(true), "REALITY requires enabled TLS and uTLS");
        }
    }
    if let Some(value) = map.get("ech") {
        let ech = object(value)?;
        fields(ech, &["enabled", "config", "pq_signature_schemes_enabled", "dynamic_record_sizing_disabled"])?;
        for key in ["enabled", "pq_signature_schemes_enabled", "dynamic_record_sizing_disabled"] { boolean(ech, key)?; }
        if let Some(config) = ech.get("config") { string_list(config, 32, 4096, true)?; }
        ensure!(ech.get("enabled").and_then(Value::as_bool) != Some(true) || ech.contains_key("config"),
            "Enabled ECH requires inline public configuration");
    }
    if matches!(map.get("engine").and_then(Value::as_str), Some("windows" | "apple")) {
        ensure!(!map.contains_key("utls") && !map.contains_key("reality"), "System TLS engine cannot use uTLS or REALITY");
    }
    Ok(())
}

fn validate_transport(value: &Value) -> Result<()> {
    let map = object(value)?;
    let kind = string(map, "type", 32, true)?.unwrap_or("");
    let allowed: &[&str] = match kind {
        "http" => &["type", "host", "path", "method", "headers", "idle_timeout", "ping_timeout"],
        "ws" => &["type", "path", "headers", "max_early_data", "early_data_header_name"],
        "quic" => &["type"],
        "grpc" => &["type", "service_name", "idle_timeout", "ping_timeout", "permit_without_stream"],
        "httpupgrade" => &["type", "host", "path", "headers"],
        _ => bail!("Unsupported connection transport"),
    };
    fields(map, allowed)?;
    for key in ["path", "method", "service_name", "early_data_header_name"] { string(map, key, 2048, false)?; }
    if let Some(host) = map.get("host") { string_list(host, 16, 253, false)?; }
    integer(map, "max_early_data", u32::MAX as u64, false)?;
    boolean(map, "permit_without_stream")?; duration(map, "idle_timeout")?; duration(map, "ping_timeout")?;
    if let Some(headers) = map.get("headers") {
        let headers = object(headers)?; ensure!(headers.len() <= 32, "Too many connection transport headers");
        for (name, value) in headers {
            ensure!(!name.is_empty() && name.len() <= 128 && name.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)), "Invalid connection transport header name");
            string_list(value, 16, 2048, false)?;
        }
    }
    Ok(())
}

fn validate_multiplex(value: &Value) -> Result<()> {
    let map = object(value)?;
    fields(map, &["enabled", "protocol", "max_connections", "min_streams", "max_streams", "padding", "brutal"])?;
    boolean(map, "enabled")?; boolean(map, "padding")?;
    choice(map, "protocol", &["", "h2mux", "smux", "yamux"])?;
    for key in ["max_connections", "min_streams", "max_streams"] { integer(map, key, u32::MAX as u64, false)?; }
    if let Some(brutal) = map.get("brutal") {
        let brutal = object(brutal)?; fields(brutal, &["enabled", "up_mbps", "down_mbps"])?; boolean(brutal, "enabled")?;
        integer(brutal, "up_mbps", u32::MAX as u64, false)?; integer(brutal, "down_mbps", u32::MAX as u64, false)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn freshness_window_is_inclusive_and_overflow_safe() {
        for generated in [700, 1_000, 1_300] { super::validate_freshness(generated, 1_000).unwrap(); }
        for generated in [0, -1, 699, 1_301, i64::MAX] { assert!(super::validate_freshness(generated, 1_000).is_err()); }
        assert!(super::validate_freshness(1, u64::MAX).is_err());
    }
}
