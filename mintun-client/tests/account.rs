use mintun_client::{account::{self, AccountClient, AccountSnapshot, InboundOption}, models::ProxyEndpoint};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpListener};
use tokio_util::sync::CancellationToken;

const UUID: &str = "11111111-2222-4333-8444-555555555555";

fn snapshot() -> AccountSnapshot {
    AccountSnapshot {
        format: 1, generated_at: 1, subject: hex::encode(Sha256::digest(UUID.as_bytes())),
        enabled: true, expires_at: None, activation_pending: false, traffic_limit_bytes: None,
        upload_bytes: 0, download_bytes: 0, inbounds: vec![],
    }
}

fn inbound(protocol: &str) -> InboundOption {
    let mut outbound = json!({"type":protocol,"server":"vpn.example.org","server_port":443,
        "tls":{"enabled":true,"server_name":"vpn.example.org","insecure":false}});
    if protocol != "hysteria2" { outbound["uuid"] = UUID.into(); }
    if matches!(protocol, "tuic" | "hysteria2") { outbound["password"] = "synthetic-account-password".into(); }
    InboundOption { id: 1, label: "Choice".into(), protocol: protocol.into(), available: true,
        unavailable_reason: String::new(), outbound_json: Some(outbound.to_string()) }
}

fn edit_template(inbound: &mut InboundOption, edit: impl FnOnce(&mut Value)) {
    let mut value: Value = serde_json::from_str(inbound.outbound_json.as_ref().unwrap()).unwrap();
    edit(&mut value);
    inbound.outbound_json = Some(value.to_string());
}

#[test]
fn cache_validation_binds_identity_without_requiring_freshness() {
    let mut value = snapshot();
    account::validate(&value, UUID).unwrap();
    assert!(account::validate(&value, "22222222-3333-4444-8555-666666666666").is_err());
    value.subject.make_ascii_uppercase();
    assert!(account::validate(&value, UUID).is_err());
    assert!(account::validate(&snapshot(), "AAAAAAAA-2222-4333-8444-555555555555").is_err());
    assert!(account::validate(&snapshot(), "00000000-0000-0000-0000-000000000000").is_err());
}

#[test]
fn metadata_bounds_and_access_flags_are_enforced() {
    let mut value = snapshot();
    value.inbounds = vec![inbound("vless"), inbound("tuic")];
    assert!(account::validate(&value, UUID).is_err());
    value.inbounds[1].id = 2;
    account::validate(&value, UUID).unwrap();
    value.enabled = false;
    assert!(account::validate(&value, UUID).is_err());
    let mut item = inbound("unsupported");
    item.available = false;
    item.unavailable_reason = "Not supported".into();
    item.outbound_json = None;
    account::validate_inbound(&item).unwrap();
    item.outbound_json = Some("{}".into());
    assert!(account::validate_inbound(&item).is_err());
    let mut value = snapshot();
    value.expires_at = Some(0);
    assert!(account::validate(&value, UUID).is_err());
    value.expires_at = None;
    value.traffic_limit_bytes = Some(0);
    assert!(account::validate(&value, UUID).is_err());
    value.traffic_limit_bytes = None;
    value.inbounds = (1..=129).map(|id| { let mut item = inbound("vless"); item.id = id; item }).collect();
    assert!(account::validate(&value, UUID).is_err());
}

#[test]
fn client_templates_preserve_public_certificates_and_reality() {
    for protocol in ["vless", "vmess", "tuic", "hysteria2"] {
        let mut item = inbound(protocol);
        edit_template(&mut item, |value| {
            value["tls"]["certificate"] = json!(["-----BEGIN CERTIFICATE-----", "cHVibGlj", "-----END CERTIFICATE-----"]);
            value["tag"] = "client-outbound-443".into();
            if protocol == "vless" {
                value["tls"]["utls"] = json!({"enabled":true,"fingerprint":"chrome"});
                value["tls"]["reality"] = json!({"enabled":true,"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","short_id":"0123456789abcdef"});
                value["flow"] = "xtls-rprx-vision".into();
                value["tls"]["ech"] = json!({"enabled":true,"config":["-----BEGIN ECH CONFIGS-----", "cHVibGlj", "-----END ECH CONFIGS-----"]});
            }
        });
        account::validate_inbound(&item).unwrap();
    }
}

#[test]
fn client_templates_preserve_typed_operational_dial_options() {
    for protocol in ["vless", "vmess", "tuic", "hysteria2"] {
        let mut item = inbound(protocol);
        edit_template(&mut item, |value| {
            value["connect_timeout"] = "10s".into();
            value["tcp_keep_alive"] = "15s".into();
            value["tcp_keep_alive_interval"] = "2.5s".into();
            value["tcp_fast_open"] = true.into();
            value["tcp_multi_path"] = false.into();
            value["udp_fragment"] = true.into();
        });
        account::validate_inbound(&item).unwrap();
        for key in ["tcp_fast_open", "tcp_multi_path", "udp_fragment"] {
            let mut invalid = item.clone();
            edit_template(&mut invalid, |value| value[key] = "true".into());
            assert!(account::validate_inbound(&invalid).is_err());
        }
        for key in ["connect_timeout", "tcp_keep_alive", "tcp_keep_alive_interval"] {
            let mut invalid = item.clone();
            edit_template(&mut invalid, |value| value[key] = json!(10));
            assert!(account::validate_inbound(&invalid).is_err());
            edit_template(&mut invalid, |value| value[key] = "10seconds".into());
            assert!(account::validate_inbound(&invalid).is_err());
        }
    }
    let mut item = inbound("vless");
    edit_template(&mut item, |value| value["transport"] = json!({}));
    assert!(account::validate_inbound(&item).is_err());
}

#[test]
fn templates_reject_unsafe_or_cross_protocol_fields_without_echoing_values() {
    for (protocol, field, value) in [
        ("vless", "tag", json!("../stolen-tag")), ("vless", "detour", json!("direct")),
        ("vless", "users", json!([{"uuid":"secret-server-user"}])),
        ("vless", "password", json!("unexpected-password")), ("tuic", "flow", json!("xtls-rprx-vision")),
        ("hysteria2", "realm", json!({"server_url":"file:///secret"})),
    ] {
        let mut item = inbound(protocol);
        edit_template(&mut item, |outbound| outbound[field] = value);
        let error = account::validate_inbound(&item).err().unwrap().to_string();
        assert!(!error.contains("stolen-tag") && !error.contains("secret-server-user") && !error.contains("unexpected-password"));
    }
    for field in ["key", "key_path", "certificate_path", "client_key", "client_key_path", "private_key"] {
        let mut item = inbound("vless");
        edit_template(&mut item, |value| value["tls"][field] = json!("secret-material"));
        assert!(account::validate_inbound(&item).is_err());
    }
    let mut item = inbound("vless");
    edit_template(&mut item, |value| value["tls"]["insecure"] = true.into());
    assert!(account::validate_inbound(&item).is_err());
    let mut item = inbound("tuic");
    edit_template(&mut item, |value| value["tls"]["utls"] = json!({"enabled":true,"fingerprint":"chrome"}));
    assert!(account::validate_inbound(&item).is_err());
    let mut item = inbound("vless");
    item.outbound_json = Some(format!("{{\"type\":\"vless\",\"type\":\"vless\",\"uuid\":\"{UUID}\",\"server\":\"vpn.example.org\",\"server_port\":443}}"));
    assert!(account::validate_inbound(&item).is_err());
}

#[test]
fn wire_schema_rejects_unknown_and_duplicate_properties() {
    let text = serde_json::to_string(&snapshot()).unwrap();
    let unknown = text.replacen('{', "{\"extra\":true,", 1);
    assert!(serde_json::from_str::<AccountSnapshot>(&unknown).is_err());
    let duplicate = text.replacen('{', "{\"format\":1,", 1);
    assert!(serde_json::from_str::<AccountSnapshot>(&duplicate).is_err());
    let item = serde_json::to_string(&inbound("vless")).unwrap();
    assert!(serde_json::from_str::<InboundOption>(&item.replacen('{', "{\"id\":1,", 1)).is_err());
    let mut missing: Value = serde_json::from_str(&text).unwrap();
    missing.as_object_mut().unwrap().remove("expiresAt");
    assert!(serde_json::from_value::<AccountSnapshot>(missing).is_err());
    let mut unknown: Value = serde_json::from_str(&item).unwrap();
    unknown["privateField"] = true.into();
    assert!(serde_json::from_value::<InboundOption>(unknown).is_err());
}

// An ephemeral loopback SOCKS peer terminates the tunnel itself: no real VPN,
// bridge port, DNS lookup, or external connection participates in these tests.
async fn socks_response(status: &str, extra_headers: &str, body: String) -> (AccountClient, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let response = format!("HTTP/1.1 {status}\r\nConnection: close\r\n{extra_headers}\r\n{body}");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut hello = [0; 2]; stream.read_exact(&mut hello).await.unwrap();
        assert_eq!(hello[0], 5);
        let mut methods = vec![0; hello[1] as usize]; stream.read_exact(&mut methods).await.unwrap();
        assert!(methods.contains(&2)); stream.write_all(&[5, 2]).await.unwrap();
        let mut auth = [0; 2]; stream.read_exact(&mut auth).await.unwrap(); assert_eq!(auth[0], 1);
        let mut username = vec![0; auth[1] as usize]; stream.read_exact(&mut username).await.unwrap();
        let password_len = stream.read_u8().await.unwrap();
        let mut password = vec![0; password_len as usize]; stream.read_exact(&mut password).await.unwrap();
        assert!(username == b"test-user" && password == b"test-password");
        stream.write_all(&[1, 0]).await.unwrap();
        let mut connect = [0; 4]; stream.read_exact(&mut connect).await.unwrap();
        assert_eq!(&connect[..3], &[5, 1, 0]);
        match connect[3] {
            1 => { let mut ip = [0; 4]; stream.read_exact(&mut ip).await.unwrap(); assert_eq!(ip, [127, 0, 0, 1]); }
            3 => { let len = stream.read_u8().await.unwrap(); let mut host = vec![0; len as usize]; stream.read_exact(&mut host).await.unwrap(); assert!(host == b"127.0.0.1"); }
            _ => panic!("unexpected SOCKS address family"),
        }
        assert_eq!(stream.read_u16().await.unwrap(), 2099);
        stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            assert!(request.len() < 8192); request.push(stream.read_u8().await.unwrap());
        }
        let request = String::from_utf8(request).unwrap();
        assert!(request.starts_with("GET /v1/account HTTP/1.1\r\n"));
        assert!(request.to_ascii_lowercase().contains(&format!("authorization: bearer {UUID}\r\n")));
        // An early size-limit rejection can close the peer before it reads a large body.
        let _ = stream.write_all(response.as_bytes()).await;
    });
    let client = AccountClient::new(&ProxyEndpoint { port, username: "test-user".into(), password: "test-password".into() }).unwrap();
    (client, server)
}

#[tokio::test]
async fn fetch_uses_authenticated_socks_and_rejects_stale_or_future_data() {
    for offset in [0i64, -600, 600] {
        let mut value = snapshot();
        value.generated_at = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64 + offset;
        let body = serde_json::to_string(&value).unwrap();
        let (client, server) = socks_response("200 OK", &format!("Content-Length: {}\r\n", body.len()), body).await;
        let result = client.fetch(UUID, &CancellationToken::new()).await;
        assert_eq!(result.is_ok(), offset == 0);
        server.await.unwrap();
    }
}

#[tokio::test]
async fn redirects_and_oversize_responses_are_never_followed_or_accepted() {
    for (status, headers, body) in [
        ("302 Found", "Location: http://invalid.example/secret\r\nContent-Length: 0\r\n", String::new()),
        ("200 OK", "Content-Length: 524289\r\n", String::new()),
        ("200 OK", "", " ".repeat(524289)),
    ] {
        let (client, server) = socks_response(status, headers, body).await;
        let error = client.fetch(UUID, &CancellationToken::new()).await.err().unwrap().to_string();
        assert!(!error.contains(UUID) && !error.contains("test-password") && !error.contains("invalid.example"));
        server.await.unwrap();
    }
}

#[tokio::test]
async fn pre_cancelled_fetch_does_not_open_a_connection() {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let client = AccountClient::new(&ProxyEndpoint { port: listener.local_addr().unwrap().port(), username: "test-user".into(), password: "test-password".into() }).unwrap();
    let cancel = CancellationToken::new(); cancel.cancel();
    assert!(client.fetch(UUID, &cancel).await.is_err());
    assert!(tokio::time::timeout(std::time::Duration::from_millis(25), listener.accept()).await.is_err());
}

#[tokio::test]
async fn cancellation_interrupts_an_in_flight_socks_handshake() {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let client = AccountClient::new(&ProxyEndpoint { port: listener.local_addr().unwrap().port(),
        username: "test-user".into(), password: "test-password".into() }).unwrap();
    let cancel = CancellationToken::new();
    let token = cancel.clone();
    let request = tokio::spawn(async move { client.fetch(UUID, &token).await });
    let (_connection, _) = tokio::time::timeout(std::time::Duration::from_secs(2), listener.accept()).await.unwrap().unwrap();
    cancel.cancel();
    let result = tokio::time::timeout(std::time::Duration::from_secs(1), request).await.unwrap().unwrap();
    assert!(result.is_err());
}
