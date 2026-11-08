use crate::models::{EncryptedConfig, FeedIdentity, Invitation, ProfileContent};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::AeadInPlace};
use anyhow::{Result, anyhow, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, FixedOffset};
use p256::{ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier}, pkcs8::DecodePublicKey};
use serde_json::Value;
use serde::de::{self, DeserializeOwned, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, fmt, ops::Deref};
use zeroize::{Zeroize, Zeroizing};

pub const MAXIMUM_PLAINTEXT_BYTES: usize = 4 * 1024 * 1024;
pub const MAXIMUM_ENVELOPE_BYTES: usize = 6 * 1024 * 1024;
const SIGNATURE_CONTEXT: &[u8] = b"MinTun.Config.v1\0";
const FEED_CONTEXT: &[u8] = b"MinTun.Feed.v1\0";

pub fn read_invitation(text: &str) -> Result<(Invitation, ProfileContent)> {
    let invitation: Invitation = parse_strict(text.as_bytes(), MAXIMUM_ENVELOPE_BYTES)?;
    ensure!(invitation.format == 1, "Unsupported invitation format.");
    let content = open(&invitation.feed, &invitation.initial_config)?;
    Ok((invitation, content))
}

pub fn decrypt_profile(feed: &FeedIdentity, text: &str) -> Result<ProfileContent> {
    let envelope: EncryptedConfig = parse_strict(text.as_bytes(), MAXIMUM_ENVELOPE_BYTES)?;
    open(feed, &envelope)
}

fn open(feed: &FeedIdentity, envelope: &EncryptedConfig) -> Result<ProfileContent> {
    validate_feed(feed)?;
    ensure!(envelope.format == 1, "Unsupported encrypted profile format.");
    let mut payload = Zeroizing::new(decode(&envelope.payload, 29, MAXIMUM_PLAINTEXT_BYTES + 28)?);
    let signature = Signature::from_slice(&decode(&envelope.signature, 64, 64)?)
        .map_err(|_| anyhow!("Invalid profile signature."))?;
    let verifier = import_public_key(&feed.signing_public_key)?;
    let hash = Sha256::new().chain_update(SIGNATURE_CONTEXT).chain_update(payload.as_slice()).finalize();
    verifier.verify_prehash(&hash, &signature).map_err(|_| anyhow!("Подпись издателя недействительна. Получите исходный файл приглашения у провайдера."))?;
    let key = Zeroizing::new(decode(&feed.encryption_key, 32, 32)?);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| anyhow!("Invalid encryption key."))?;
    let nonce: [u8; 12] = payload[..12].try_into().expect("validated nonce length");
    let tag: [u8; 16] = payload[payload.len() - 16..].try_into().expect("validated tag length");
    let end = payload.len() - 16;
    cipher.decrypt_in_place_detached(Nonce::from_slice(&nonce), &associated_data(feed)?, &mut payload[12..end], (&tag).into())
        .map_err(|_| anyhow!("Profile authentication failed."))?;
    let content: ProfileContent = parse_strict(&payload[12..end], MAXIMUM_PLAINTEXT_BYTES)?;
    validate_profile(&content)?;
    ensure!(content.profile_id == feed.id, "Profile belongs to a different feed.");
    Ok(content)
}

pub fn validate_feed(feed: &FeedIdentity) -> Result<()> {
    let id = uuid::Uuid::parse_str(&feed.id).map_err(|_| anyhow!("Invalid feed identity."))?;
    ensure!(!id.is_nil() && feed.id == id.hyphenated().to_string(), "Feed identity must be a canonical nonempty UUID.");
    ensure!(feed.format == 1 && !feed.name.trim().is_empty() && utf16_len(&feed.name) <= 200 && !feed.name.chars().any(char::is_control), "Invalid feed name or format.");
    ensure!(!feed.update_url.is_empty() && utf16_len(&feed.update_url) <= 4096 && !feed.update_url.chars().any(|c| c.is_whitespace() || c.is_control()), "Invalid update URL.");
    let url = url::Url::parse(&feed.update_url).map_err(|_| anyhow!("Invalid update URL."))?;
    ensure!(url.scheme() == "https" && url.host_str().is_some_and(|s| !s.is_empty()) && url.username().is_empty() && url.password().is_none() && url.fragment().is_none(), "Updates require an HTTPS URL without credentials or fragment.");
    // Url normalizes backslashes and dot-segments; do not rewrite the signed URL.
    let _key = Zeroizing::new(decode(&feed.encryption_key, 32, 32)?);
    import_public_key(&feed.signing_public_key)?;
    Ok(())
}

pub fn validate_profile(profile: &ProfileContent) -> Result<()> {
    ensure!(profile.format == 1 && profile.revision > 0, "Invalid signed profile metadata.");
    let id = uuid::Uuid::parse_str(&profile.profile_id).map_err(|_| anyhow!("Invalid profile identity."))?;
    ensure!(!id.is_nil() && profile.profile_id == id.hyphenated().to_string(), "Invalid profile identity.");
    published(&profile.published_utc)?;
    ensure!(is_version(&profile.minimum_core_version), "Invalid minimum core version.");
    ensure!(!profile.outbound_tag.trim().is_empty() && utf16_len(&profile.outbound_tag) <= 200 && !profile.outbound_tag.chars().any(char::is_control), "Invalid selected outbound tag.");
    let config = SecretJson(parse_strict::<Value>(profile.config_json.as_bytes(), MAXIMUM_PLAINTEXT_BYTES)?);
    let root = config.as_object().ok_or_else(|| anyhow!("Configuration must be an object."))?;
    let outbounds = root.get("outbounds").and_then(Value::as_array).ok_or_else(|| anyhow!("Configuration requires outbounds."))?;
    let mut tags = HashSet::new();
    let mut selected = None;
    for outbound in outbounds {
        let object = outbound.as_object().ok_or_else(|| anyhow!("Invalid outbound object."))?;
        let tag = match object.get("tag") {
            Some(value) => {
                let tag = value.as_str().ok_or_else(|| anyhow!("Invalid outbound tag."))?;
                ensure!(!tag.trim().is_empty() && tags.insert(tag), "Outbound tags must be nonempty and unique.");
                Some(tag)
            }
            None => None,
        };
        let is_selected = tag == Some(profile.outbound_tag.as_str());
        ensure!(!contains_uuid(outbound, is_selected), "Only the selected outbound may contain a UUID credential.");
        if is_selected { selected = Some(object); }
    }
    let selected = selected.ok_or_else(|| anyhow!("Selected outbound is missing."))?;
    ensure!(matches!(selected.get("type").and_then(Value::as_str), Some("vless" | "vmess")), "Selected outbound must use VLESS or VMess.");
    let value = selected.get("uuid").and_then(Value::as_str).ok_or_else(|| anyhow!("Selected outbound requires a sanitized UUID."))?;
    // Legacy TryParseExact("D") accepts case differences but not compact/braced UUIDs.
    ensure!(is_hyphenated_uuid(value) && uuid::Uuid::parse_str(value).is_ok_and(|id| id.is_nil()), "Shared profile must not contain publisher credentials.");
    ensure!(root.get("log").and_then(Value::as_object).and_then(|log| log.get("disabled")) == Some(&Value::Bool(true)), "Shared profiles must disable logging.");
    Ok(())
}

pub fn check_revision(current: &ProfileContent, next: &ProfileContent) -> Result<()> {
    ensure!(current.profile_id == next.profile_id, "Update belongs to a different profile.");
    ensure!(next.revision >= current.revision, "Profile rollback was rejected.");
    if next.revision == current.revision {
        ensure!(next.config_json == current.config_json && next.outbound_tag == current.outbound_tag && next.minimum_core_version == current.minimum_core_version && published(&next.published_utc)? == published(&current.published_utc)?, "Profile content changed without a revision increase.");
    }
    Ok(())
}

fn published(text: &str) -> Result<DateTime<FixedOffset>> {
    ensure!(text.len() <= 64 && text.as_bytes().get(10) == Some(&b'T') && !text.ends_with('z'), "Invalid publication timestamp.");
    if let Some((_, fraction)) = text.split_once('.') {
        let digits = fraction.bytes().take_while(u8::is_ascii_digit).count();
        ensure!((1..=16).contains(&digits), "Invalid publication timestamp precision.");
    }
    let date = DateTime::parse_from_rfc3339(text).map_err(|_| anyhow!("Invalid publication timestamp."))?;
    ensure!(date.offset().local_minus_utc() == 0, "Publication timestamp must be UTC.");
    // System.Text.Json accepts up to 16 fractional digits, truncating after
    // seven, and DateTimeOffset has a 100-nanosecond resolution.
    use chrono::{Datelike, Timelike};
    ensure!((1..=9999).contains(&date.year()) && date.nanosecond() < 1_000_000_000, "Invalid publication timestamp.");
    let date = date.with_nanosecond(date.nanosecond() / 100 * 100).ok_or_else(|| anyhow!("Invalid publication timestamp."))?;
    ensure!(!(date.year() == 1 && date.month() == 1 && date.day() == 1 && date.hour() == 0 && date.minute() == 0 && date.second() == 0 && date.nanosecond() == 0), "Publication timestamp must not be default.");
    Ok(date)
}

fn is_version(text: &str) -> bool {
    if text.is_empty() || text.len() > 128 { return false; }
    let mut plus = text.split('+');
    let left = plus.next().unwrap_or_default();
    if let Some(build) = plus.next() {
        if !identifiers(build, false) || plus.next().is_some() { return false; }
    }
    let (core, pre) = match left.split_once('-') { Some((core, pre)) => (core, Some(pre)), None => (left, None) };
    let mut parts = core.split('.');
    for _ in 0..3 {
        let Some(part) = parts.next() else { return false; };
        if part.is_empty() || !part.bytes().all(|c| c.is_ascii_digit()) || (part.len() > 1 && part.starts_with('0')) { return false; }
    }
    parts.next().is_none() && pre.is_none_or(|pre| identifiers(pre, true))
}

fn identifiers(text: &str, reject_numeric_zero: bool) -> bool {
    text.split('.').all(|part| !part.is_empty() && part.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-') && !(reject_numeric_zero && part.len() > 1 && part.starts_with('0') && part.bytes().all(|c| c.is_ascii_digit())))
}

fn contains_uuid(value: &Value, allow_root: bool) -> bool {
    match value {
        Value::Object(map) => map.iter().any(|(key, value)| (key.eq_ignore_ascii_case("uuid") && !(allow_root && key == "uuid")) || contains_uuid(value, false)),
        Value::Array(values) => values.iter().any(|value| contains_uuid(value, false)),
        _ => false,
    }
}

fn is_hyphenated_uuid(text: &str) -> bool {
    text.len() == 36 && text.bytes().enumerate().all(|(i, c)| if [8, 13, 18, 23].contains(&i) { c == b'-' } else { c.is_ascii_hexdigit() })
}
fn utf16_len(text: &str) -> usize { text.encode_utf16().count() }

fn decode(text: &str, minimum: usize, maximum: usize) -> Result<Vec<u8>> {
    ensure!(!text.is_empty() && text.len() <= maximum.div_ceil(3) * 4 && !text.chars().any(char::is_whitespace), "Invalid cryptographic encoding.");
    let mut bytes = Zeroizing::new(STANDARD.decode(text).map_err(|_| anyhow!("Invalid cryptographic encoding."))?);
    let canonical = Zeroizing::new(STANDARD.encode(bytes.as_slice()));
    ensure!((minimum..=maximum).contains(&bytes.len()) && canonical.as_str() == text, "Invalid cryptographic length or noncanonical Base64.");
    Ok(std::mem::take(&mut *bytes))
}

fn import_public_key(text: &str) -> Result<VerifyingKey> {
    VerifyingKey::from_public_key_der(&decode(text, 1, 256)?).map_err(|_| anyhow!("Publisher key must be a complete P-256 SubjectPublicKeyInfo."))
}

fn associated_data(feed: &FeedIdentity) -> Result<Vec<u8>> {
    let spki = decode(&feed.signing_public_key, 1, 256)?;
    let mut bytes = Vec::with_capacity(FEED_CONTEXT.len() + 20 + feed.id.len() + feed.name.len() + feed.update_url.len() + spki.len());
    bytes.extend_from_slice(FEED_CONTEXT);
    bytes.extend_from_slice(&feed.format.to_be_bytes());
    for field in [feed.id.as_bytes(), feed.name.as_bytes(), feed.update_url.as_bytes(), spki.as_slice()] {
        bytes.extend_from_slice(&(field.len() as u32).to_be_bytes());
        bytes.extend_from_slice(field);
    }
    Ok(bytes)
}

// Scan first without retaining decrypted strings: serde_json::Value otherwise silently
// overwrites duplicate fields. Typed deserialization separately enforces exact schemas.
pub(crate) fn parse_strict<T: DeserializeOwned>(bytes: &[u8], maximum: usize) -> Result<T> {
    ensure!(!bytes.is_empty() && bytes.len() <= maximum, "JSON document exceeds the allowed size.");
    let mut parser = serde_json::Deserializer::from_slice(bytes);
    StrictSeed(0).deserialize(&mut parser).map_err(|_| anyhow!("Invalid JSON, duplicate property, or excessive nesting."))?;
    parser.end().map_err(|_| anyhow!("Trailing data after JSON document."))?;
    serde_json::from_slice(bytes).map_err(|_| anyhow!("Unsupported JSON document structure."))
}

struct StrictSeed(usize);
impl<'de> DeserializeSeed<'de> for StrictSeed {
    type Value = ();
    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> std::result::Result<(), D::Error> {
        deserializer.deserialize_any(StrictVisitor(self.0))
    }
}
struct StrictVisitor(usize);
impl<'de> Visitor<'de> for StrictVisitor {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("strict JSON") }
    fn visit_bool<E: de::Error>(self, _: bool) -> std::result::Result<(), E> { Ok(()) }
    fn visit_i64<E: de::Error>(self, _: i64) -> std::result::Result<(), E> { Ok(()) }
    fn visit_u64<E: de::Error>(self, _: u64) -> std::result::Result<(), E> { Ok(()) }
    fn visit_f64<E: de::Error>(self, _: f64) -> std::result::Result<(), E> { Ok(()) }
    fn visit_str<E: de::Error>(self, _: &str) -> std::result::Result<(), E> { Ok(()) }
    fn visit_unit<E: de::Error>(self) -> std::result::Result<(), E> { Ok(()) }
    fn visit_none<E: de::Error>(self) -> std::result::Result<(), E> { Ok(()) }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<(), A::Error> {
        if self.0 >= 64 { return Err(de::Error::custom("JSON nesting limit")); }
        while seq.next_element_seed(StrictSeed(self.0 + 1))?.is_some() {}
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<(), A::Error> {
        if self.0 >= 64 { return Err(de::Error::custom("JSON nesting limit")); }
        let mut names = HashSet::new();
        while let Some(name) = map.next_key::<String>()? {
            if !names.insert(name) { return Err(de::Error::custom("duplicate JSON property")); }
            map.next_value_seed(StrictSeed(self.0 + 1))?;
        }
        Ok(())
    }
}

struct SecretJson(Value);
impl Deref for SecretJson { type Target = Value; fn deref(&self) -> &Value { &self.0 } }
impl Drop for SecretJson {
    fn drop(&mut self) {
        fn erase(value: &mut Value) {
            match value {
                Value::String(text) => text.zeroize(),
                Value::Array(values) => values.iter_mut().for_each(erase),
                Value::Object(map) => {
                    for (mut key, mut value) in std::mem::take(map) { key.zeroize(); erase(&mut value); }
                }
                _ => (),
            }
        }
        erase(&mut self.0);
    }
}
