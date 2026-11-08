use anyhow::{Result, anyhow, ensure};
use rand::RngCore;
use serde_json::{Value, json};
use std::net::TcpListener;
use uuid::Uuid;
use zeroize::{Zeroize,Zeroizing};
use crate::{account, models::{ClientState, ProfileContent, ProxyEndpoint, RuntimeConfiguration}, paths::Paths, preferences::{ConnectionPreferences, DIRECT_APPLICATIONS, DIRECT_DOMAIN_SUFFIXES}};

pub const UPDATER_TAG: &str = "mintun-updater";

pub(crate) struct SensitiveJson(pub Value);
impl Drop for SensitiveJson {
    fn drop(&mut self) {
        fn erase(value:&mut Value) {
            match value {Value::String(s)=>s.zeroize(),Value::Array(a)=>for value in a {erase(value)},Value::Object(o)=>for value in o.values_mut(){erase(value)},_=>{}}
        }
        erase(&mut self.0);
    }
}

pub fn build(profile: &ProfileContent, state: &ClientState, paths: &Paths, allow_empty_uuid: bool) -> Result<RuntimeConfiguration> {
    state.preferences.validate()?;
    let uuid=if allow_empty_uuid && state.uuid.is_empty() {"00000000-0000-0000-0000-000000000000"} else {state.uuid.as_str()};
    let id = Uuid::parse_str(uuid).map_err(|_| anyhow!("Enter a UUID in xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx format"))?;
    ensure!(uuid.len() == 36 && uuid.as_bytes().iter().enumerate().all(|(i,c)| if [8,13,18,23].contains(&i) { *c == b'-' } else { c.is_ascii_hexdigit() }), "UUID must use the canonical hyphenated format");
    ensure!(allow_empty_uuid || !id.is_nil(), "A non-empty UUID is required");
    let mut document=SensitiveJson(serde_json::from_str(&profile.config_json).map_err(|_| anyhow!("Invalid profile configuration JSON"))?);
    let root=document.0.as_object_mut().ok_or_else(|| anyhow!("Configuration must be an object"))?;
    let outbounds = root.get_mut("outbounds").and_then(Value::as_array_mut).ok_or_else(|| anyhow!("Missing outbounds"))?;
    let targets: Vec<_> = outbounds.iter_mut().filter(|o| o.get("tag").and_then(Value::as_str) == Some(profile.outbound_tag.as_str())).collect();
    ensure!(targets.len() == 1, "Profile must select exactly one outbound");
    for target in targets {
        if let Some(selected_id) = state.preferences.selected_inbound_id {
            let cache = state.account.as_ref().ok_or_else(|| anyhow!("Refresh account information before selecting an inbound"))?;
            ensure!(cache.profile_id == profile.profile_id, "Account information belongs to a different profile");
            account::validate(&cache.snapshot, &state.uuid)?;
            ensure!(cache.snapshot.enabled, "The account is disabled");
            let inbound = cache.snapshot.inbounds.iter().find(|inbound| inbound.id == selected_id)
                .ok_or_else(|| anyhow!("The selected inbound is no longer in the account catalog"))?;
            ensure!(inbound.available, "The selected inbound is unavailable; refresh account information");
            account::validate_inbound(inbound)?;
            let template = inbound.outbound_json.as_deref().ok_or_else(|| anyhow!("The selected inbound has no client configuration"))?;
            let mut selected = SensitiveJson(serde_json::from_str(template).map_err(|_| anyhow!("Invalid selected inbound configuration"))?);
            let object = selected.0.as_object_mut().ok_or_else(|| anyhow!("Selected inbound must be an object"))?;
            object.insert("tag".into(), json!(profile.outbound_tag));
            std::mem::swap(target, &mut selected.0);
        }
        let protocol = target.get("type").and_then(Value::as_str);
        ensure!(matches!(protocol, Some("vless" | "vmess" | "tuic" | "hysteria2")), "Selected outbound protocol is unsupported");
        if matches!(protocol, Some("vless" | "vmess")) {
            if state.preferences.selected_inbound_id.is_none() {
                target.as_object_mut().ok_or_else(|| anyhow!("Invalid outbound"))?.insert("uuid".into(), Value::String(id.hyphenated().to_string()));
            }
        } else {
            ensure!(state.preferences.selected_inbound_id.is_some(), "QUIC credentials require an available account inbound");
        }
        apply_fingerprint(target, state.preferences.fingerprint.as_deref())?;
    }
    apply_preferences(root, &state.preferences, &profile.outbound_tag)?;
    root.insert("log".into(), json!({"disabled":true}));
    let inbounds = root.get_mut("inbounds").and_then(Value::as_array_mut).ok_or_else(|| anyhow!("A TUN inbound is required"))?;
    ensure!(!inbounds.iter().any(|i| i.get("tag").and_then(Value::as_str) == Some(UPDATER_TAG)), "The mintun-updater inbound tag is reserved");
    let tunnels: Vec<_> = inbounds.iter_mut().filter(|i| i.get("type").and_then(Value::as_str) == Some("tun")).collect();
    ensure!(tunnels.len() == 1, "Exactly one TUN inbound is required");
    let mut interface_name = String::new();
    for tun in tunnels {
        interface_name = tun.get("interface_name").and_then(Value::as_str).filter(|s| !s.trim().is_empty()).unwrap_or("MinTun").to_owned();
        #[cfg(target_os="macos")] {
            // Darwin only supports utun<number>; migrate Windows-oriented profile names.
            let valid=interface_name.strip_prefix("utun").is_some_and(|suffix|!suffix.is_empty() && suffix.bytes().all(|b|b.is_ascii_digit()));
            if !valid {
                interface_name=(64..1024).map(|n|format!("utun{n}")).find(|name|std::ffi::CString::new(name.as_str()).is_ok_and(|name|unsafe {libc::if_nametoindex(name.as_ptr())}==0)).ok_or_else(||anyhow!("No free Darwin TUN interface name"))?;
            }
        }
        tun.as_object_mut().ok_or_else(|| anyhow!("Invalid TUN inbound"))?.insert("interface_name".into(), json!(interface_name));
    }
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST,0))?;
    let port = listener.local_addr()?.port();
    let mut password=Zeroizing::new([0u8;24]);rand::rngs::OsRng.fill_bytes(&mut password[..]);
    let proxy=ProxyEndpoint {port,username:"mintun".into(),password:hex::encode(&password[..])};
    inbounds.push(json!({"type":"socks","tag":UPDATER_TAG,"listen":"127.0.0.1","listen_port":port,"users":[{"username":proxy.username,"password":proxy.password}]}));
    let route = root.entry("route").or_insert_with(|| json!({})).as_object_mut().ok_or_else(|| anyhow!("route must be an object"))?;
    let rules = route.entry("rules").or_insert_with(|| json!([])).as_array_mut().ok_or_else(|| anyhow!("route.rules must be an array"))?;
    rules.insert(0,json!({"inbound":[UPDATER_TAG],"action":"route","outbound":profile.outbound_tag}));
    if let Some(cache) = root.get_mut("experimental").and_then(|e| e.get_mut("cache_file")).and_then(Value::as_object_mut) {
        cache.insert("path".into(), json!(paths.cache));
    }
    let working_directory = paths.root.join("runtime");
    std::fs::create_dir_all(&working_directory)?;
    #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; std::fs::set_permissions(&working_directory,std::fs::Permissions::from_mode(0o700))?; }
    Ok(RuntimeConfiguration { json:serde_json::to_string(root)?,proxy,interface_name,working_directory })
}

fn apply_fingerprint(outbound: &mut Value, fingerprint: Option<&str>) -> Result<()> {
    let Some(fingerprint) = fingerprint else { return Ok(()) };
    if !matches!(outbound.get("type").and_then(Value::as_str), Some("vless" | "vmess"))
        || outbound.get("network").and_then(Value::as_str) == Some("udp")
        || !matches!(outbound.pointer("/transport/type").and_then(Value::as_str), None | Some("http" | "ws" | "httpupgrade" | "grpc"))
    {
        return Ok(());
    }
    let Some(tls) = outbound.get_mut("tls").and_then(Value::as_object_mut) else { return Ok(()) };
    if tls.get("enabled").and_then(Value::as_bool) != Some(true)
        || !matches!(tls.get("engine").and_then(Value::as_str), None | Some("" | "go"))
    {
        return Ok(());
    }
    let utls = tls.entry("utls").or_insert_with(|| json!({})).as_object_mut()
        .ok_or_else(|| anyhow!("Outbound TLS uTLS settings must be an object"))?;
    utls.insert("enabled".into(), json!(true));
    utls.insert("fingerprint".into(), json!(fingerprint));
    Ok(())
}

fn process_basename_regex(name: &str) -> String {
    // Go/RE2 process_name is case-sensitive, including on Windows in alpha.13.
    let mut pattern = String::from("(?i)(?:^|[\\\\/])");
    for c in name.chars() {
        if "\\.+*?()|[]{}^$".contains(c) { pattern.push('\\'); }
        pattern.push(c);
    }
    pattern.push('$');
    pattern
}

fn prerequisite(rule: &Value) -> bool {
    matches!(rule.get("action").and_then(Value::as_str), Some("sniff" | "resolve" | "route-options" | "hijack-dns"))
}

fn has_matcher(rule: &Value) -> bool {
    [
        "inbound", "protocol", "network", "domain", "domain_suffix", "domain_keyword", "domain_regex",
        "process_name", "process_path", "process_path_regex", "ip_is_private", "ip_cidr",
        "source_ip_is_private", "source_ip_cidr", "rule_set", "rules", "port", "port_range",
    ].iter().any(|key| rule.get(*key).is_some())
}

fn apply_preferences(root: &mut serde_json::Map<String, Value>, preferences: &ConnectionPreferences, outbound_tag: &str) -> Result<()> {
    let outbounds = root.get_mut("outbounds").and_then(Value::as_array_mut).ok_or_else(|| anyhow!("Missing outbounds"))?;
    let direct_tag = if let Some(tag) = outbounds.iter().find(|outbound| {
        outbound.get("type").and_then(Value::as_str) == Some("direct") && outbound.get("tag").and_then(Value::as_str).is_some()
    }).and_then(|outbound| outbound.get("tag")).and_then(Value::as_str) {
        tag.to_owned()
    } else {
        let mut tag = "mintun-direct".to_owned();
        while outbounds.iter().any(|outbound| outbound.get("tag").and_then(Value::as_str) == Some(tag.as_str())) { tag.push('-'); }
        outbounds.push(json!({"type":"direct","tag":tag}));
        tag
    };
    let direct_tags: Vec<_> = outbounds.iter().filter(|outbound| outbound.get("type").and_then(Value::as_str) == Some("direct"))
        .filter_map(|outbound| outbound.get("tag").and_then(Value::as_str)).map(str::to_owned).collect();
    let route = root.entry("route").or_insert_with(|| json!({})).as_object_mut().ok_or_else(|| anyhow!("route must be an object"))?;
    let rules = route.entry("rules").or_insert_with(|| json!([])).as_array_mut().ok_or_else(|| anyhow!("route.rules must be an array"))?;
    // Only insert after the leading infrastructure/direct-exception prefix.
    // In particular, do not hoist later geo/IP direct rules ahead of signed proxy rules.
    let position = rules.iter().take_while(|rule| {
        let direct = rule.get("outbound").and_then(Value::as_str).is_some_and(|tag| direct_tags.iter().any(|direct| direct == tag));
        prerequisite(rule) || (direct && has_matcher(rule))
    }).count();
    let remaining = rules.split_off(position);
    rules.push(json!({"process_path_regex":DIRECT_APPLICATIONS.iter().map(|name| process_basename_regex(name)).collect::<Vec<_>>(),"action":"route","outbound":direct_tag}));
    rules.push(json!({"domain_suffix":DIRECT_DOMAIN_SUFFIXES,"action":"route","outbound":direct_tag}));
    if !preferences.applications.is_empty() {
        rules.push(json!({"process_path_regex":preferences.applications.iter().map(|name| process_basename_regex(name)).collect::<Vec<_>>(),"action":"route","outbound":outbound_tag}));
    }
    if !preferences.domain_suffixes.is_empty() {
        rules.push(json!({"domain_suffix":preferences.domain_suffixes,"action":"route","outbound":outbound_tag}));
    }
    rules.extend(remaining);
    if preferences.domain_suffixes.is_empty() { return Ok(()) }
    apply_domain_dns(root, &preferences.domain_suffixes, outbound_tag)
}

fn apply_domain_dns(root: &mut serde_json::Map<String, Value>, suffixes: &[String], outbound_tag: &str) -> Result<()> {
    let dns = root.get_mut("dns").and_then(Value::as_object_mut).ok_or_else(|| anyhow!("Custom domains require a signed proxy DNS resolver"))?;
    let servers = dns.get("servers").and_then(Value::as_array).ok_or_else(|| anyhow!("Custom domains require signed DNS servers"))?;
    let proxy_servers: Vec<_> = servers.iter().filter(|server| server.get("detour").and_then(Value::as_str) == Some(outbound_tag))
        .filter_map(|server| server.get("tag").and_then(Value::as_str)).filter(|tag| !tag.is_empty()).collect();
    let resolver = if proxy_servers.len() == 1 {
        proxy_servers[0]
    } else if let Some(final_tag) = dns.get("final").and_then(Value::as_str).filter(|tag| proxy_servers.contains(tag)) {
        final_tag
    } else {
        anyhow::bail!("Cannot identify one safe signed proxy DNS resolver for custom domains");
    }.to_owned();
    ensure!(servers.iter().filter(|server| server.get("tag").and_then(Value::as_str) == Some(resolver.as_str())).count() == 1, "Proxy DNS resolver tag must be unique");
    let rules = dns.entry("rules").or_insert_with(|| json!([])).as_array_mut().ok_or_else(|| anyhow!("dns.rules must be an array"))?;
    let position = rules.iter().take_while(|rule| {
        matches!(rule.get("action").and_then(Value::as_str), Some("evaluate" | "route-options"))
            || rule.get("ip_is_private").and_then(Value::as_bool) == Some(true)
            || ["process_name", "process_path", "process_path_regex"].iter().any(|key| rule.get(*key).is_some())
            || rule.get("domain_suffix").is_some_and(|suffixes| {
                let local = |s: &str| matches!(s.trim_start_matches('.'), "local" | "localhost" | "lan" | "home.arpa" | "in-addr.arpa" | "ip6.arpa");
                suffixes.as_str().is_some_and(local) || suffixes.as_array().is_some_and(|items| !items.is_empty() && items.iter().all(|item| item.as_str().is_some_and(local)))
            })
    }).count();
    rules.insert(position, json!({"domain_suffix":suffixes,"action":"route","server":resolver}));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn state(uuid: &str) -> ClientState {
        let mut state = ClientState::default();
        state.uuid = uuid.into();
        state
    }
    #[test] fn rejects_noncanonical_uuid_before_accessing_profile() {
        let p = ProfileContent { format:1,profile_id:"fixture".into(),revision:1,published_utc:"2026-01-01T00:00:00Z".into(),minimum_core_version:"1.0.0".into(),outbound_tag:"vpn".into(),config_json:"{}".into() };
        let root = tempfile::tempdir().unwrap();
        let paths = Paths::new(Some(root.path().to_owned())).unwrap();
        for uuid in ["00000000000000000000000000000000", "00000000-0000-0000-0000-000000000000"] { assert!(build(&p,&state(uuid),&paths,false).is_err()); }
    }
    #[test] fn first_import_preflight_allows_missing_personal_uuid_but_connect_rejects_it() {
        let profile=ProfileContent {format:1,profile_id:"fixture".into(),revision:1,published_utc:"2026-01-01T00:00:00Z".into(),minimum_core_version:"1.0.0".into(),outbound_tag:"vpn".into(),config_json:json!({
            "inbounds":[{"type":"tun"}],"outbounds":[{"type":"vless","tag":"vpn","uuid":"00000000-0000-0000-0000-000000000000"}]
        }).to_string()};
        let directory=tempfile::tempdir().unwrap();let paths=Paths::new(Some(directory.path().to_owned())).unwrap();
        let preflight=build(&profile,&state(""),&paths,true).unwrap();
        let config:Value=serde_json::from_str(&preflight.json).unwrap();
        assert_eq!(config["outbounds"][0]["uuid"],"00000000-0000-0000-0000-000000000000");
        assert!(build(&profile,&state(""),&paths,false).is_err());
        assert!(build(&profile,&state("00000000-0000-0000-0000-000000000000"),&paths,false).is_err());
        assert!(build(&profile,&state("not-a-uuid"),&paths,true).is_err());
        assert!(build(&profile,&state(" "),&paths,true).is_err());
    }
    #[test] fn injects_only_selected_uuid_and_authenticated_vpn_update_route() {
        let p=ProfileContent {format:1,profile_id:"fixture".into(),revision:1,published_utc:"2026-01-01T00:00:00Z".into(),minimum_core_version:"1.0.0".into(),outbound_tag:"vpn".into(),config_json:json!({
            "log":{"level":"debug"},"inbounds":[{"type":"tun"}],
            "outbounds":[{"type":"vless","tag":"vpn","uuid":"old"},{"type":"vmess","tag":"other","uuid":"untouched"}],
            "route":{"rules":[{"action":"reject"}]},"experimental":{"cache_file":{"enabled":true,"path":"unsafe.db"}}
        }).to_string()};
        let root=tempfile::tempdir().unwrap();let paths=Paths::new(Some(root.path().to_owned())).unwrap();
        let runtime=build(&p,&state("12345678-1234-4234-8234-123456789abc"),&paths,false).unwrap();
        let config:Value=serde_json::from_str(&runtime.json).unwrap();
        assert_eq!(config["outbounds"][0]["uuid"],"12345678-1234-4234-8234-123456789abc");
        assert_eq!(config["outbounds"][1]["uuid"],"untouched");assert_eq!(config["log"],json!({"disabled":true}));
        assert_eq!(config["route"]["rules"][0],json!({"inbound":[UPDATER_TAG],"action":"route","outbound":"vpn"}));
        assert_eq!(config["inbounds"][1]["listen"],"127.0.0.1");
        assert_eq!(config["inbounds"][1]["listen_port"],runtime.proxy.port);
        assert_eq!(config["inbounds"][1]["users"][0]["password"],runtime.proxy.password);
        assert_eq!(runtime.proxy.password.len(),48);assert_eq!(config["experimental"]["cache_file"]["path"],json!(paths.cache));
        assert!(!runtime.working_directory.join("config.json").exists());
    }
    const UUID: &str = "12345678-1234-4234-8234-123456789abc";

    fn fixture() -> ProfileContent {
        ProfileContent { format:1, profile_id:"fixture".into(), revision:1, published_utc:"2026-01-01T00:00:00Z".into(),
            minimum_core_version:"1.0.0".into(), outbound_tag:"vpn".into(), config_json:json!({
                "inbounds":[{"type":"tun","interface_name":"MinTun","auto_route":true}],
                "outbounds":[{"type":"vless","tag":"vpn","uuid":"old","server":"203.0.113.1","server_port":443,
                    "flow":"xtls-rprx-vision","tls":{"enabled":true,"server_name":"example.org",
                    "reality":{"enabled":true,"public_key":"fixture-public-key","short_id":"aabb"},
                    "utls":{"enabled":true,"fingerprint":"chrome"}}},{"type":"direct","tag":"baseline-direct"}],
                "route":{"rules":[
                    {"protocol":"dns","action":"hijack-dns"},
                    {"action":"sniff"},{"action":"resolve"},
                    {"ip_is_private":true,"action":"route","outbound":"baseline-direct"},
                    {"process_name":["OneDrive.exe"],"action":"route","outbound":"baseline-direct"},
                    {"action":"route","outbound":"vpn"}
                ],"rule_set":[{"type":"remote","tag":"signed-rules","format":"binary","url":"https://example.org/rules.srs","download_detour":"vpn"}]},
                "dns":{"servers":[{"type":"local","tag":"local"},{"type":"https","tag":"signed-proxy-dns","server":"1.1.1.1","detour":"vpn"}],
                    "rules":[{"domain_suffix":["local","home.arpa"],"action":"route","server":"local"},
                        {"action":"route","server":"local"}]},
                "experimental":{"cache_file":{"enabled":true,"path":"old-cache"}}
            }).to_string() }
    }

    fn render(profile: &ProfileContent, state: &ClientState) -> Value {
        let directory = tempfile::tempdir().unwrap();
        let paths = Paths::new(Some(directory.path().to_owned())).unwrap();
        let runtime = build(profile, state, &paths, false).unwrap();
        serde_json::from_str(&runtime.json).unwrap()
    }

    fn catalog_state(protocol: &str) -> ClientState {
        use sha2::{Digest, Sha256};
        let outbound = match protocol {
            "vless" | "vmess" => json!({"type":protocol,"server":"203.0.113.2","server_port":443,"uuid":if protocol == "vmess" { "87654321-1234-4234-8234-123456789abc" } else { UUID },
                "tls":{"enabled":true,"server_name":"example.org","utls":{"enabled":true,"fingerprint":"chrome"}}}),
            "tuic" => json!({"type":"tuic","server":"203.0.113.2","server_port":443,"uuid":"87654321-1234-4234-8234-123456789abc","password":"fixture-tuic",
                "tls":{"enabled":true,"server_name":"example.org","alpn":["h3"]}}),
            "hysteria2" => json!({"type":"hysteria2","server":"203.0.113.2","server_port":443,"password":"fixture-hy2",
                "tls":{"enabled":true,"server_name":"example.org","alpn":["h3"]}}),
            _ => unreachable!(),
        };
        let mut state = state(UUID);
        state.preferences.selected_inbound_id = Some(7);
        state.account = Some(serde_json::from_value(json!({"profileId":"fixture","snapshot":{
            "format":1,"generatedAt":1,"subject":hex::encode(Sha256::digest(UUID.as_bytes())),
            "enabled":true,"expiresAt":null,"activationPending":false,"trafficLimitBytes":null,
            "uploadBytes":0,"downloadBytes":0,"inbounds":[{"id":7,"label":"fixture inbound","protocol":protocol,
                "available":true,"unavailableReason":"","outboundJson":outbound.to_string()}]
        }})).unwrap());
        state
    }

    #[test]
    fn custom_apps_and_domains_are_or_rules_after_infrastructure_and_direct_exceptions() {
        let profile = fixture();
        let signed = profile.config_json.clone();
        let mut state = state(UUID);
        state.preferences.applications = vec!["Browser.EXE".into()];
        state.preferences.domain_suffixes = vec!["video.example".into()];
        let config = render(&profile, &state);
        let rules = config["route"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["inbound"], json!([UPDATER_TAG]));
        assert_eq!(rules[1]["action"], "hijack-dns");
        assert_eq!(rules[2]["action"], "sniff");
        assert_eq!(rules[3]["action"], "resolve");
        assert_eq!(rules[4]["ip_is_private"], true);
        assert_eq!(rules[5]["process_name"], json!(["OneDrive.exe"]));
        let app = rules.iter().position(|rule| rule["process_path_regex"] == json!(["(?i)(?:^|[\\\\/])Browser\\.EXE$"])).unwrap();
        let domain = rules.iter().position(|rule| rule["domain_suffix"] == json!(["video.example"])).unwrap();
        assert!(app > 5 && domain > 5);
        assert!(rules[app].get("domain_suffix").is_none());
        assert!(rules[domain].get("process_path_regex").is_none());
        assert_eq!(rules[app]["outbound"], "vpn");
        assert_eq!(rules[domain]["outbound"], "vpn");
        let steam = rules.iter().position(|rule| rule["domain_suffix"].as_array().is_some_and(|domains| domains.contains(&json!("steamcontent.com")))).unwrap();
        assert!(steam < app && steam < domain);
        assert_eq!(rules[steam]["outbound"], "baseline-direct");
        assert!(rules.iter().take(app).any(|rule| rule["process_path_regex"].as_array().is_some_and(|patterns| patterns.contains(&json!("(?i)(?:^|[\\\\/])steam\\.exe$")))));
        assert_eq!(config["dns"]["rules"][0]["server"], "local");
        assert_eq!(config["dns"]["rules"][1], json!({"domain_suffix":["video.example"],"action":"route","server":"signed-proxy-dns"}));
        assert_eq!(config["dns"]["rules"][2]["server"], "local");
        assert_eq!(config["route"]["rule_set"][0]["download_detour"], "vpn");
        assert_eq!(config["inbounds"][0]["auto_route"], true);
        assert_eq!(profile.config_json, signed);
    }

    #[test]
    fn rejects_unsafe_settings_even_when_state_bypasses_text_parsers() {
        let profile = fixture();
        let directory = tempfile::tempdir().unwrap();
        let paths = Paths::new(Some(directory.path().to_owned())).unwrap();
        let mut state = state(UUID);
        for app in ["STEAM.exe", "qBitTorrent.exe", "../Browser.exe"] {
            state.preferences.applications = vec![app.into()];
            assert!(build(&profile, &state, &paths, false).is_err());
        }
        state.preferences.applications.clear();
        for domain in ["com", "cdn.steamcontent.com", "utorrent.com", "*.example.org"] {
            state.preferences.domain_suffixes = vec![domain.into()];
            assert!(build(&profile, &state, &paths, false).is_err());
        }
    }

    #[test]
    fn fingerprint_override_preserves_reality_and_signed_profile() {
        let profile = fixture();
        let signed = profile.config_json.clone();
        let mut state = state(UUID);
        state.preferences.fingerprint = Some("randomized".into());
        let config = render(&profile, &state);
        assert_eq!(config["outbounds"][0]["tls"]["utls"]["fingerprint"], "randomized");
        assert_eq!(config["outbounds"][0]["tls"]["reality"]["public_key"], "fixture-public-key");
        assert_eq!(config["outbounds"][0]["tls"]["reality"]["short_id"], "aabb");
        assert_eq!(config["outbounds"][0]["tls"]["server_name"], "example.org");
        assert_eq!(config["outbounds"][0]["flow"], "xtls-rprx-vision");
        assert_eq!(profile.config_json, signed);
    }

    #[test]
    fn materializes_own_catalog_under_signed_tag_for_all_supported_protocols() {
        let profile = fixture();
        for protocol in ["vless", "vmess", "tuic", "hysteria2"] {
            let mut state = catalog_state(protocol);
            state.preferences.fingerprint = Some("firefox".into());
            let config = render(&profile, &state);
            let outbound = &config["outbounds"][0];
            assert_eq!(outbound["tag"], "vpn");
            assert_eq!(outbound["type"], protocol);
            assert_eq!(outbound["server"], "203.0.113.2");
            if matches!(protocol, "vless" | "vmess") {
                assert_eq!(outbound["uuid"], if protocol == "vmess" { "87654321-1234-4234-8234-123456789abc" } else { UUID });
                assert_eq!(outbound["tls"]["utls"]["fingerprint"], "firefox");
            } else {
                assert!(outbound["tls"].get("utls").is_none());
                assert!(outbound["tls"].get("reality").is_none());
                assert_eq!(outbound["tls"]["alpn"], json!(["h3"]));
                assert_eq!(outbound["password"], if protocol == "tuic" { "fixture-tuic" } else { "fixture-hy2" });
                if protocol == "tuic" { assert_eq!(outbound["uuid"], "87654321-1234-4234-8234-123456789abc"); }
            }
            assert_eq!(config["route"]["rules"][0]["outbound"], "vpn");
            assert_eq!(config["dns"]["servers"][1]["detour"], "vpn");
            assert_eq!(config["route"]["rule_set"][0]["download_detour"], "vpn");
        }
    }

    #[test]
    fn rejects_catalog_selection_without_profile_and_uuid_binding_or_availability() {
        let profile = fixture();
        let directory = tempfile::tempdir().unwrap();
        let paths = Paths::new(Some(directory.path().to_owned())).unwrap();
        let mut missing = state(UUID);
        missing.preferences.selected_inbound_id = Some(7);
        assert!(build(&profile, &missing, &paths, false).is_err());
        let mut wrong_profile = catalog_state("tuic");
        wrong_profile.account.as_mut().unwrap().profile_id = "another-profile".into();
        assert!(build(&profile, &wrong_profile, &paths, false).is_err());
        let mut wrong_uuid = catalog_state("tuic");
        wrong_uuid.uuid = "87654321-1234-4234-8234-123456789abc".into();
        assert!(build(&profile, &wrong_uuid, &paths, false).is_err());
        let mut unavailable = catalog_state("tuic");
        let inbound = &mut unavailable.account.as_mut().unwrap().snapshot.inbounds[0];
        inbound.available = false;
        inbound.unavailable_reason = "not assigned".into();
        inbound.outbound_json = None;
        assert!(build(&profile, &unavailable, &paths, false).is_err());
        let mut absent = catalog_state("tuic");
        absent.preferences.selected_inbound_id = Some(99);
        assert!(build(&profile, &absent, &paths, false).is_err());
        let mut disabled = catalog_state("tuic");
        disabled.account.as_mut().unwrap().snapshot.enabled = false;
        assert!(build(&profile, &disabled, &paths, false).is_err());
        let mut duplicate = catalog_state("tuic");
        let inbounds = &mut duplicate.account.as_mut().unwrap().snapshot.inbounds;
        inbounds.push(inbounds[0].clone());
        assert!(build(&profile, &duplicate, &paths, false).is_err());
        let mut unsafe_template = catalog_state("tuic");
        let inbound = &mut unsafe_template.account.as_mut().unwrap().snapshot.inbounds[0];
        let mut template: Value = serde_json::from_str(inbound.outbound_json.as_deref().unwrap()).unwrap();
        template["detour"] = json!("baseline-direct");
        inbound.outbound_json = Some(template.to_string());
        assert!(build(&profile, &unsafe_template, &paths, false).is_err());
    }

    #[test]
    fn no_selection_uses_signed_outbound_even_with_unrelated_cached_catalog() {
        let profile = fixture();
        let mut state = catalog_state("tuic");
        state.preferences.selected_inbound_id = None;
        state.account.as_mut().unwrap().profile_id = "unrelated".into();
        let config = render(&profile, &state);
        assert_eq!(config["outbounds"][0]["type"], "vless");
        assert_eq!(config["outbounds"][0]["server"], "203.0.113.1");
        assert_eq!(config["outbounds"][0]["uuid"], UUID);
    }

    #[test]
    fn custom_domain_dns_rejects_missing_or_ambiguous_proxy_resolver_without_fallback() {
        let mut profile = fixture();
        let mut state = state(UUID);
        state.preferences.domain_suffixes = vec!["video.example".into()];
        let directory = tempfile::tempdir().unwrap();
        let paths = Paths::new(Some(directory.path().to_owned())).unwrap();
        let mut document: Value = serde_json::from_str(&profile.config_json).unwrap();
        document["dns"]["servers"][1]["detour"] = json!("baseline-direct");
        profile.config_json = document.to_string();
        assert!(build(&profile, &state, &paths, false).is_err());
        document["dns"]["servers"][1]["detour"] = json!("vpn");
        document["dns"]["servers"].as_array_mut().unwrap().push(json!({"type":"https","tag":"other-proxy-dns","server":"8.8.8.8","detour":"vpn"}));
        profile.config_json = document.to_string();
        assert!(build(&profile, &state, &paths, false).is_err());
        document["dns"]["final"] = json!("signed-proxy-dns");
        profile.config_json = document.to_string();
        assert_eq!(render(&profile, &state)["dns"]["rules"][1]["server"], "signed-proxy-dns");
    }

    #[test]
    fn fingerprint_never_enables_utls_on_quic_transport_udp_or_native_tls_engine() {
        let mut profile = fixture();
        let mut state = state(UUID);
        state.preferences.fingerprint = Some("firefox".into());
        for variant in ["quic", "udp", "windows", "disabled"] {
            let mut document: Value = serde_json::from_str(&fixture().config_json).unwrap();
            let outbound = &mut document["outbounds"][0];
            outbound["tls"].as_object_mut().unwrap().remove("utls");
            match variant {
                "quic" => outbound["transport"] = json!({"type":"quic"}),
                "udp" => outbound["network"] = json!("udp"),
                "windows" => outbound["tls"]["engine"] = json!("windows"),
                "disabled" => outbound["tls"]["enabled"] = json!(false),
                _ => unreachable!(),
            }
            profile.config_json = document.to_string();
            assert!(render(&profile, &state)["outbounds"][0]["tls"].get("utls").is_none());
            assert_eq!(state.preferences.fingerprint.as_deref(), Some("firefox"));
        }
    }

    #[test]
    fn regex_treats_literal_basename_metacharacters_as_literals() {
        assert_eq!(process_basename_regex("Browser (Work)+.exe"), "(?i)(?:^|[\\\\/])Browser \\(Work\\)\\+\\.exe$");
    }
    #[test]
    fn preserves_signed_rule_order_without_hoisting_later_ip_or_geo_direct_rules() {
        let mut profile = fixture();
        let mut document: Value = serde_json::from_str(&profile.config_json).unwrap();
        let original = document["route"]["rules"].as_array_mut().unwrap();
        let later_ip = json!({"ip_cidr":["198.51.100.0/24"],"action":"route","outbound":"baseline-direct"});
        let later_geo = json!({"rule_set":["geo-direct"],"action":"route","outbound":"baseline-direct"});
        original.push(later_ip.clone());
        original.push(later_geo.clone());
        original.push(json!({"action":"resolve","strategy":"prefer_ipv6"}));
        let signed_rules = original.clone();
        profile.config_json = document.to_string();
        let mut state = state(UUID);
        state.preferences.applications = vec!["Browser.EXE".into()];
        let config = render(&profile, &state);
        let rules = config["route"]["rules"].as_array().unwrap();
        let mut after = 0;
        for signed in &signed_rules {
            let relative = rules[after..].iter().position(|rule| rule == signed).unwrap();
            after += relative + 1;
        }
        let proxy = rules.iter().position(|rule| rule == &json!({"action":"route","outbound":"vpn"})).unwrap();
        let custom = rules.iter().position(|rule| rule["process_path_regex"] == json!(["(?i)(?:^|[\\\\/])Browser\\.EXE$"])).unwrap();
        let private = rules.iter().position(|rule| rule["ip_is_private"] == true).unwrap();
        let direct_app = rules.iter().position(|rule| rule["process_name"] == json!(["OneDrive.exe"])).unwrap();
        assert!(private < custom && direct_app < custom && custom < proxy);
        assert!(rules.iter().position(|rule| rule == &later_ip).unwrap() > proxy);
        assert!(rules.iter().position(|rule| rule == &later_geo).unwrap() > proxy);
    }

    #[test]
    fn shared_cdn_guards_only_cover_known_steam_host_subtrees() {
        let config = render(&fixture(), &state(UUID));
        let rules = config["route"]["rules"].as_array().unwrap();
        let guard = rules.iter().find(|rule| {
            rule["domain_suffix"].as_array().is_some_and(|domains| domains.contains(&json!("steamcdn-a.akamaihd.net")))
        }).unwrap();
        assert_eq!(guard["outbound"], "baseline-direct");
        let domains = guard["domain_suffix"].as_array().unwrap();
        assert!(!domains.contains(&json!("akamaihd.net")));
        assert!(!domains.contains(&json!("photos.akamaihd.net")));
        assert!(domains.contains(&json!("steamuserimages-a.akamaihd.net")));
        assert!(domains.contains(&json!("steamcommunity-a.akamaihd.net")));
    }
}
