use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const FINGERPRINTS: &[&str] = &[
    "chrome", "firefox", "edge", "safari", "360", "qq", "ios", "android", "random", "randomized",
];

// These are literal known-client names, not a claim to detect renamed/embedded clients.
pub(crate) const DIRECT_APPLICATIONS: &[&str] = &[
    "steam.exe", "steamwebhelper.exe", "steamservice.exe", "qbittorrent.exe", "qbittorrent-nox.exe",
    "bittorrent.exe", "utorrent.exe", "µtorrent.exe", "μtorrent.exe", "utweb.exe", "btweb.exe",
    "deluge.exe", "deluge-gtk.exe", "deluge-debug.exe", "deluged.exe", "deluged-debug.exe",
    "deluge-console.exe", "deluge-web.exe", "deluge-web-debug.exe", "transmission-qt.exe",
    "transmission-daemon.exe", "tixati.exe", "biglybt.exe", "vuze.exe", "bitcomet.exe",
    "bitcomet_x64.exe", "webtorrent.exe",
];
pub(crate) const DIRECT_DOMAIN_SUFFIXES: &[&str] = &[
    "steampowered.com", "steamcommunity.com", "steamgames.com", "steamusercontent.com",
    "steamcontent.com", "steamstatic.com", "steamcdn-a.akamaihd.net",
    "steamuserimages-a.akamaihd.net", "steamcommunity-a.akamaihd.net", "bittorrent.com", "utorrent.com",
    "qbittorrent.org", "deluge-torrent.org", "transmissionbt.com", "tixati.com", "biglybt.com",
    "vuze.com", "bitcomet.com", "webtorrent.io",
];
const MAX_ENTRIES: usize = 128;
const MAX_INPUT_BYTES: usize = 64 * 1024;

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectionPreferences {
    pub selected_inbound_id: Option<u64>,
    pub fingerprint: Option<String>,
    pub domain_suffixes: Vec<String>,
    pub applications: Vec<String>,
}

impl ConnectionPreferences {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.selected_inbound_id != Some(0), "Select a valid inbound ID");
        ensure!(self.fingerprint.as_deref().is_none_or(|s| FINGERPRINTS.contains(&s)), "Unsupported TLS fingerprint");
        ensure!(self.domain_suffixes.len() <= MAX_ENTRIES && self.applications.len() <= MAX_ENTRIES, "At most 128 domains and 128 applications are allowed");
        let mut domains = HashSet::new();
        for suffix in &self.domain_suffixes {
            ensure!(normalize_domain(suffix)? == *suffix, "Domain suffixes must use canonical lowercase IDNA form");
            ensure!(domains.insert(suffix), "Duplicate domain suffix");
        }
        let mut apps = HashSet::new();
        for app in &self.applications {
            validate_application(app)?;
            ensure!(apps.insert(app.to_lowercase()), "Duplicate application name");
        }
        Ok(())
    }
}

fn entries(input: &str) -> Result<impl Iterator<Item = &str>> {
    ensure!(input.len() <= MAX_INPUT_BYTES, "Connection rule input is too long");
    Ok(input.split([',', ';', '\n', '\r']).map(str::trim).filter(|s| !s.is_empty()))
}

pub fn parse_domain_suffixes(input: &str) -> Result<Vec<String>> {
    let mut result = Vec::new();
    let mut seen = HashSet::new();
    for entry in entries(input)? {
        ensure!(result.len() < MAX_ENTRIES, "At most 128 domain suffixes are allowed");
        let suffix = normalize_domain(entry)?;
        ensure!(seen.insert(suffix.clone()), "Duplicate domain suffix");
        result.push(suffix);
    }
    Ok(result)
}

pub fn parse_applications(input: &str) -> Result<Vec<String>> {
    let mut result = Vec::new();
    let mut seen = HashSet::new();
    for entry in entries(input)? {
        ensure!(result.len() < MAX_ENTRIES, "At most 128 applications are allowed");
        validate_application(entry)?;
        ensure!(seen.insert(entry.to_lowercase()), "Duplicate application name");
        result.push(entry.to_owned());
    }
    Ok(result)
}

fn normalize_domain(input: &str) -> Result<String> {
    let bare = input.strip_prefix('.').unwrap_or(input);
    let bare = bare.strip_suffix('.').unwrap_or(bare);
    ensure!(!bare.is_empty() && bare.len() <= 1024 && !bare.chars().any(|c| c.is_whitespace() || c.is_control() || "/\\:*?@#%[]".contains(c)), "Enter a bare domain suffix, not a URL, IP, path or wildcard");
    let url::Host::Domain(domain) = url::Host::parse(bare).map_err(|_| anyhow::anyhow!("Invalid domain suffix"))? else {
        anyhow::bail!("IP addresses cannot be domain suffixes");
    };
    let domain = domain.to_ascii_lowercase();
    ensure!(domain.len() <= 253 && domain.split('.').all(|label| {
        !label.is_empty() && label.len() <= 63 && !label.starts_with('-') && !label.ends_with('-')
            && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    }), "Invalid domain suffix labels");
    ensure!(!DIRECT_DOMAIN_SUFFIXES.iter().any(|blocked| suffixes_overlap(&domain, blocked)), "Steam and torrent domains (including parent and child suffixes) cannot be proxied by custom rules");
    ensure!(domain.contains('.'), "Enter a domain with at least two labels");
    Ok(domain)
}

fn suffixes_overlap(a: &str, b: &str) -> bool {
    a == b || a.strip_suffix(b).is_some_and(|prefix| prefix.ends_with('.'))
        || b.strip_suffix(a).is_some_and(|prefix| prefix.ends_with('.'))
}

fn validate_application(app: &str) -> Result<()> {
    ensure!(!app.is_empty() && app.encode_utf16().count() <= 255 && app.trim() == app
        && !app.chars().any(|c| c.is_control() || "/\\:*?\"<>|".contains(c)), "Enter an exact Windows .exe basename without paths, arguments or wildcards");
    let lower = app.to_lowercase();
    let stem = lower.strip_suffix(".exe").filter(|s| !s.is_empty()).ok_or_else(|| anyhow::anyhow!("Application names must end in .exe"))?;
    let device = stem.split('.').next().unwrap_or_default();
    ensure!(!matches!(device, "con" | "prn" | "aux" | "nul")
        && !(device.len() == 4 && (device.starts_with("com") || device.starts_with("lpt")) && matches!(device.as_bytes()[3], b'1'..=b'9')), "Reserved Windows executable basename");
    ensure!(!DIRECT_APPLICATIONS.contains(&lower.as_str()), "Steam and torrent applications cannot be proxied by custom rules");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalizes_idna_and_preserves_application_casing() {
        assert_eq!(parse_domain_suffixes(" .EXAMPLE.ORG.; bücher.example\nvideo.example ").unwrap(), ["example.org", "xn--bcher-kva.example", "video.example"]);
        assert_eq!(parse_applications("Browser.EXE; My Browser.exe\r\nCode.exe").unwrap(), ["Browser.EXE", "My Browser.exe", "Code.exe"]);
    }

    #[test]
    fn rejects_invalid_domains_and_protected_suffix_tree_overlap() {
        for value in ["https://example.org", "127.0.0.1", "127.1", "[::1]", "*.example.org", "a..example.org", "-a.example.org", "a_.example.org", "example.org:443", "a/b.org", "a%2eb.org", "com", "net", "org", "io", "SteamContent.COM", "cdn.steamcontent.com", "qbittorrent.org"] {
            assert!(parse_domain_suffixes(value).is_err(), "accepted {value}");
        }
        assert!(parse_domain_suffixes("steamcontent.com.example.org").is_ok());
        assert!(parse_domain_suffixes("notsteamcontent.com").is_ok());
        assert!(parse_domain_suffixes("example.org;.EXAMPLE.ORG.").is_err());
        assert!(parse_domain_suffixes("photos.akamaihd.net").is_ok());
        assert!(parse_domain_suffixes("cdn.steamcdn-a.akamaihd.net").is_err());
        assert!(parse_domain_suffixes("akamaihd.net").is_err());
    }

    #[test]
    fn rejects_forbidden_and_nonliteral_apps_without_banning_other_categories() {
        for value in ["StEaM.ExE", "QBITTORRENT.EXE", "μTorrent.exe", "C:\\Code.exe", "folder/Code.exe", "Code.exe --arg", "*.exe", "Code?.exe", "Code\t.exe", "CON.exe", ".exe"] {
            assert!(parse_applications(value).is_err(), "accepted {value}");
        }
        assert!(parse_applications("Code.exe;code.EXE").is_err());
        assert!(parse_applications("EpicGamesLauncher.exe;OneDrive.exe;chrome.exe;java.exe").is_ok());
    }

    #[test]
    fn bounds_counts_labels_and_application_length() {
        assert!(parse_domain_suffixes(&format!("{}.example", "a".repeat(63))).is_ok());
        let longest = ["a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(61)].join(".");
        assert_eq!(longest.len(), 253);
        assert!(parse_domain_suffixes(&longest).is_ok());
        assert!(parse_domain_suffixes(&format!("{longest}d")).is_err());
        assert!(parse_applications(&format!("{}.exe", "a".repeat(251))).is_ok());
        assert!(parse_domain_suffixes(&format!("{}.example", "a".repeat(64))).is_err());
        assert!(parse_applications(&format!("{}.exe", "a".repeat(252))).is_err());
        let domains = (0..128).map(|n| format!("x{n}.example")).collect::<Vec<_>>().join(";");
        assert_eq!(parse_domain_suffixes(&domains).unwrap().len(), 128);
        assert!(parse_domain_suffixes(&format!("{domains};overflow.example")).is_err());
        let apps = (0..128).map(|n| format!("x{n}.exe")).collect::<Vec<_>>().join(";");
        assert_eq!(parse_applications(&apps).unwrap().len(), 128);
        assert!(parse_applications(&format!("{apps};overflow.exe")).is_err());
        assert!(parse_domain_suffixes(&" ".repeat(MAX_INPUT_BYTES + 1)).is_err());
    }

    #[test]
    fn validates_stored_values_and_exact_fingerprint_choices() {
        for fingerprint in FINGERPRINTS {
            let mut preferences = ConnectionPreferences::default();
            preferences.fingerprint = Some((*fingerprint).into());
            assert!(preferences.validate().is_ok());
        }
        let mut preferences = ConnectionPreferences::default();
        preferences.fingerprint = Some("chrome_psk".into());
        assert!(preferences.validate().is_err());
        preferences.fingerprint = None;
        preferences.selected_inbound_id = Some(0);
        assert!(preferences.validate().is_err());
        preferences.selected_inbound_id = None;
        preferences.domain_suffixes = vec!["EXAMPLE.ORG".into()];
        assert!(preferences.validate().is_err());
        preferences.domain_suffixes.clear();
        preferences.applications = vec!["STEAM.EXE".into()];
        assert!(preferences.validate().is_err());
        assert!(serde_json::from_str::<ConnectionPreferences>(r#"{"selectedInboundId":null,"fingerprint":null,"domainSuffixes":[],"applications":[],"extra":true}"#).is_err());
    }
}
