use crate::{account, models::{AccountCache, ClientState, FeedIdentity, ProfileContent}, preferences::ConnectionPreferences, profile};
use anyhow::{Result, anyhow, ensure, Context};
use std::{fs::{self, File, OpenOptions}, io::{Read, Write}, path::{Path, PathBuf}};
use zeroize::Zeroizing;

const MAXIMUM_STORED_BYTES: usize = 32 * 1024 * 1024;

// The .NET client persisted this removed UI preference. Accept only that known
// legacy field while keeping canonical state and signed profile schemas strict.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StateDocument {
    #[serde(default = "state_format_one")]
    format: i32,
    #[serde(default)]
    feed: Option<FeedIdentity>,
    #[serde(default)]
    profile: Option<ProfileContent>,
    #[serde(default)]
    uuid: String,
    #[serde(default)]
    core_directory: String,
    #[serde(default)]
    preferences: ConnectionPreferences,
    #[serde(default)]
    account: Option<AccountCache>,
    #[serde(default, rename = "includePrereleases")]
    _legacy_include_prereleases: bool,
}

fn state_format_one() -> i32 { 1 }

pub fn load(path: &Path) -> Result<Option<ClientState>> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("Cannot read protected client state."),
    };
    ensure!(file.metadata()?.is_file(), "Protected state must be a regular file.");
    let size = file.metadata()?.len();
    ensure!(size > 0 && size <= MAXIMUM_STORED_BYTES as u64, "Invalid protected state size.");
    let mut bytes = Vec::with_capacity(size as usize);
    Read::by_ref(&mut file).take(MAXIMUM_STORED_BYTES as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= MAXIMUM_STORED_BYTES, "Protected state exceeds size limit.");
    let plaintext = Zeroizing::new(unprotect(path, &bytes)?);
    let document: StateDocument = profile::parse_strict(&plaintext, MAXIMUM_STORED_BYTES)?;
    let state = ClientState {
        format: document.format, feed: document.feed, profile: document.profile,
        uuid: document.uuid, core_directory: document.core_directory,
        preferences: document.preferences, account: document.account,
    };
    validate_state(&state)?;
    Ok(Some(state))
}

pub fn save(path: &Path, state: &ClientState) -> Result<()> {
    validate_state(state)?;
    let plaintext = Zeroizing::new(serde_json::to_vec(state).map_err(|_| anyhow!("Cannot serialize client state."))?);
    ensure!(!plaintext.is_empty() && plaintext.len() <= MAXIMUM_STORED_BYTES - 1024, "Client state exceeds size limit.");
    prepare_parent(path)?;
    // Key creation and ciphertext replacement must be one cross-process critical
    // section. The persistent sidecar contains no data and is never unlinked.
    #[cfg(not(target_os = "android"))]
    let _lock = state_lock(path)?;
    let encrypted = protect(path, &plaintext)?;
    ensure!(!encrypted.is_empty() && encrypted.len() <= MAXIMUM_STORED_BYTES, "Invalid protected state size.");
    atomic_write(path, &encrypted)
}

fn validate_state(state: &ClientState) -> Result<()> {
    ensure!(state.format == 1, "Unsupported protected state format.");
    if !state.uuid.is_empty() {
        ensure!(state.uuid.len() == 36 && uuid::Uuid::parse_str(&state.uuid).is_ok_and(|id| !id.is_nil()), "Invalid personal UUID in client state.");
    }
    match (&state.feed, &state.profile) {
        (Some(feed), Some(content)) => {
            profile::validate_feed(feed)?;
            profile::validate_profile(content)?;
            ensure!(feed.id == content.profile_id, "Protected state profile identity mismatch.");
        }
        (None, None) => (),
        _ => return Err(anyhow!("Protected state must contain both feed and profile.")),
    }
    state.preferences.validate()?;
    if let Some(cache) = &state.account {
        ensure!(state.profile.as_ref().is_some_and(|profile| profile.profile_id == cache.profile_id),
            "Account cache belongs to another profile.");
        account::validate(&cache.snapshot, &state.uuid)?;
    }
    Ok(())
}

fn parent(path: &Path) -> Result<&Path> {
    path.parent().filter(|path| !path.as_os_str().is_empty()).ok_or_else(|| anyhow!("A storage file requires an explicit parent directory."))
}

fn prepare_parent(path: &Path) -> Result<()> {
    let directory = parent(path)?;
    #[cfg(unix)] {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder.create(directory)?;
        let metadata = fs::symlink_metadata(directory)?;
        ensure!(metadata.is_dir() && !metadata.file_type().is_symlink(), "Storage directory must not be a symbolic link.");
        // Do not silently chmod a pre-existing user directory into a new policy.
        ensure!(metadata.permissions().mode() & 0o077 == 0, "Storage directory must be private (mode 0700).");
    }
    #[cfg(not(unix))]
    fs::create_dir_all(directory)?;
    Ok(())
}

#[cfg(not(target_os = "android"))]
fn state_lock(path: &Path) -> Result<File> {
    use fs2::FileExt;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)] {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock = options.open(parent(path)?.join(".mintun-state.lock"))?;
    lock.lock_exclusive()?;
    Ok(lock)
}

pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    prepare_parent(path)?;
    let temporary = parent(path)?.join(format!(".mintun-{}.tmp", uuid::Uuid::new_v4().simple()));
    struct RemoveTemporary(PathBuf);
    impl Drop for RemoveTemporary { fn drop(&mut self) { let _ = fs::remove_file(&self.0); } }
    let _cleanup = RemoveTemporary(temporary.clone());
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)] {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary).context("Cannot create private replacement file.")?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    replace(&temporary, path)?;
    #[cfg(unix)]
    File::open(parent(path)?)?.sync_all()?;
    Ok(())
}

#[cfg(not(windows))]
fn replace(source: &Path, destination: &Path) -> Result<()> {
    fs::rename(source, destination).context("Cannot atomically replace storage file.")
}

#[cfg(windows)]
fn replace(source: &Path, destination: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    unsafe extern "system" { fn MoveFileExW(source: *const u16, destination: *const u16, flags: u32) -> i32; }
    let wide = |path: &Path| -> Result<Vec<u16>> {
        let mut bytes: Vec<u16> = path.as_os_str().encode_wide().collect();
        ensure!(!bytes.contains(&0), "Invalid storage file path.");
        bytes.push(0);
        Ok(bytes)
    };
    let source = wide(source)?;
    let destination = wide(destination)?;
    // Same-directory replacement, no cross-volume copy; flush-through matches the
    // legacy DPAPI store's durability and never exposes an unencrypted temporary.
    let result = unsafe { MoveFileExW(source.as_ptr(), destination.as_ptr(), 0x1 | 0x8) };
    ensure!(result != 0, "Cannot atomically replace protected storage (Windows error {}).", std::io::Error::last_os_error().raw_os_error().unwrap_or_default());
    Ok(())
}

#[cfg(windows)]
fn protect(_: &Path, bytes: &[u8]) -> Result<Vec<u8>> { dpapi(bytes, true) }
#[cfg(windows)]
fn unprotect(_: &Path, bytes: &[u8]) -> Result<Vec<u8>> { dpapi(bytes, false) }
#[cfg(target_os = "android")]
fn protect(_: &Path, bytes: &[u8]) -> Result<Vec<u8>> { crate::android::protect_state(bytes) }
#[cfg(target_os = "android")]
fn unprotect(_: &Path, bytes: &[u8]) -> Result<Vec<u8>> { crate::android::unprotect_state(bytes) }

#[cfg(windows)]
fn dpapi(bytes: &[u8], protect: bool) -> Result<Vec<u8>> {
    use std::{ffi::c_void, ptr};
    use zeroize::Zeroize;
    #[repr(C)]
    struct Blob { length: u32, data: *mut u8 }
    #[link(name = "crypt32")]
    unsafe extern "system" {
        fn CryptProtectData(input: *const Blob, description: *const u16, entropy: *const Blob, reserved: *mut c_void, prompt: *mut c_void, flags: u32, output: *mut Blob) -> i32;
        fn CryptUnprotectData(input: *const Blob, description: *mut *mut u16, entropy: *const Blob, reserved: *mut c_void, prompt: *mut c_void, flags: u32, output: *mut Blob) -> i32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" { fn LocalFree(memory: *mut c_void) -> *mut c_void; }
    struct NativeOutput(Blob);
    impl Drop for NativeOutput {
        fn drop(&mut self) {
            if !self.0.data.is_null() {
                // DPAPI owns the allocation; erase both ciphertext and plaintext.
                unsafe {
                    std::slice::from_raw_parts_mut(self.0.data, self.0.length as usize).zeroize();
                    LocalFree(self.0.data.cast());
                }
            }
        }
    }
    ensure!(!bytes.is_empty() && bytes.len() <= MAXIMUM_STORED_BYTES, "Invalid DPAPI input size.");
    let input = Blob { length: bytes.len() as u32, data: bytes.as_ptr().cast_mut() };
    let mut output = NativeOutput(Blob { length: 0, data: ptr::null_mut() });
    // No entropy, description, or LOCAL_MACHINE flag: exactly the .NET state.bin
    // format and current-user security scope, without any machine-wide changes.
    let success = unsafe {
        if protect { CryptProtectData(&input, ptr::null(), ptr::null(), ptr::null_mut(), ptr::null_mut(), 1, &mut output.0) }
        else { CryptUnprotectData(&input, ptr::null_mut(), ptr::null(), ptr::null_mut(), ptr::null_mut(), 1, &mut output.0) }
    };
    ensure!(success != 0, "Cannot open or protect state for this Windows user (error {}).", std::io::Error::last_os_error().raw_os_error().unwrap_or_default());
    ensure!(output.0.length > 0 && output.0.length as usize <= MAXIMUM_STORED_BYTES && !output.0.data.is_null(), "Invalid DPAPI result size.");
    Ok(unsafe { std::slice::from_raw_parts(output.0.data, output.0.length as usize) }.to_vec())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
const STATE_MAGIC: &[u8] = b"MinTun.State.v1\0";

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn protect(path: &Path, bytes: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::{Aead, Payload}};
    use rand::{rngs::OsRng, RngCore};
    let key = platform_key(path, !path.try_exists()?)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| anyhow!("Invalid keychain state key."))?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let encrypted = cipher.encrypt(Nonce::from_slice(&nonce), Payload { msg: bytes, aad: STATE_MAGIC })
        .map_err(|_| anyhow!("Cannot encrypt protected client state."))?;
    let mut result = Vec::with_capacity(STATE_MAGIC.len() + 12 + encrypted.len());
    result.extend_from_slice(STATE_MAGIC);
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&encrypted);
    Ok(result)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn unprotect(path: &Path, bytes: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::{Aead, Payload}};
    ensure!(bytes.starts_with(STATE_MAGIC) && bytes.len() > STATE_MAGIC.len() + 28, "Unsupported protected state format.");
    let key = platform_key(path, false)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| anyhow!("Invalid keychain state key."))?;
    cipher.decrypt(Nonce::from_slice(&bytes[STATE_MAGIC.len()..STATE_MAGIC.len() + 12]), Payload { msg: &bytes[STATE_MAGIC.len() + 12..], aad: STATE_MAGIC })
        .map_err(|_| anyhow!("Protected client state authentication failed."))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn key_account(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    use std::os::unix::ffi::OsStrExt;
    let parent = parent(path)?.canonicalize()?;
    let filename = path.file_name().ok_or_else(|| anyhow!("Invalid state filename."))?;
    let hash = Sha256::new().chain_update(b"MinTun.State.Key.v1\0").chain_update(parent.as_os_str().as_bytes()).chain_update([0]).chain_update(filename.as_bytes()).finalize();
    let mut account = String::with_capacity(64);
    use std::fmt::Write as _;
    for byte in hash { write!(&mut account, "{byte:02x}").expect("writing to String is infallible"); }
    Ok(account)
}

#[cfg(target_os = "linux")]
fn platform_key(path: &Path, create: bool) -> Result<Zeroizing<Vec<u8>>> {
    use secret_service::{blocking::SecretService, EncryptionType};
    use std::collections::HashMap;
    use rand::{rngs::OsRng, RngCore};
    let account = key_account(path)?;
    let attributes = HashMap::from([("application", "app.mintun.client"), ("purpose", "state-aes256-v1"), ("account", account.as_str())]);
    let service = SecretService::connect(EncryptionType::Dh).map_err(|_| anyhow!("Linux Secret Service is unavailable; no unencrypted fallback is permitted."))?;
    let found = service.search_items(attributes.clone()).map_err(|_| anyhow!("Cannot search Linux Secret Service."))?;
    let mut items = found.unlocked;
    items.extend(found.locked);
    ensure!(items.len() <= 1, "Ambiguous encryption keys in Linux Secret Service.");
    let key = if let Some(item) = items.first() {
        item.ensure_unlocked().map_err(|_| anyhow!("State key is locked in Linux Secret Service."))?;
        Zeroizing::new(item.get_secret().map_err(|_| anyhow!("Cannot read Secret Service state key."))?)
    } else {
        ensure!(create, "The encrypted state key is missing from Linux Secret Service.");
        let collection = service.get_default_collection().map_err(|_| anyhow!("Linux Secret Service requires a persistent default collection."))?;
        collection.ensure_unlocked().map_err(|_| anyhow!("Linux Secret Service collection is locked."))?;
        let mut key = Zeroizing::new(vec![0u8; 32]);
        OsRng.fill_bytes(&mut key);
        collection.create_item("MinTun client state encryption", attributes, &key, false, "application/octet-stream")
            .map_err(|_| anyhow!("Cannot store state encryption key in Linux Secret Service."))?;
        key
    };
    ensure!(key.len() == 32, "Invalid Linux Secret Service state key size.");
    Ok(key)
}

#[cfg(target_os = "macos")]
fn platform_key(path: &Path, create: bool) -> Result<Zeroizing<Vec<u8>>> {
    use security_framework::passwords::{get_generic_password, set_generic_password};
    use rand::{rngs::OsRng, RngCore};
    let account = key_account(path)?;
    let service = "app.mintun.client.state-aes256-v1";
    let key = match get_generic_password(service, &account) {
        Ok(key) => Zeroizing::new(key),
        Err(error) if error.code() == -25300 && create => {
            let mut key = Zeroizing::new(vec![0u8; 32]);
            OsRng.fill_bytes(&mut key);
            set_generic_password(service, &account, &key).map_err(|_| anyhow!("Cannot store state encryption key in macOS Keychain."))?;
            key
        }
        Err(_) => return Err(anyhow!("Cannot read the state key from macOS Keychain; no unencrypted fallback is permitted.")),
    };
    ensure!(key.len() == 32, "Invalid macOS Keychain state key size.");
    Ok(key)
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn legacy_document() -> Value {
        let fixture: Value = serde_json::from_slice(include_bytes!("../tests/fixtures/protocol-dotnet.json")).unwrap();
        json!({
            "format": 1,
            "feed": fixture["invitation"]["feed"],
            "profile": fixture["profile"],
            "uuid": "11111111-2222-4333-8444-555555555555",
            "coreDirectory": "C:\\Synthetic\\MinTunClient\\cores\\alpha13",
            "includePrereleases": true
        })
    }

    #[test]
    fn legacy_prerelease_preference_preserves_protected_profile_and_uuid() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.bin");
        let document = legacy_document();
        let ciphertext = protect(&path, &serde_json::to_vec(&document).unwrap()).unwrap();
        fs::write(&path, &ciphertext).unwrap();

        let loaded = load(&path);
        assert!(loaded.is_ok(), "valid legacy .NET state must load without resetting it");
        let state = loaded.unwrap().unwrap();
        assert_eq!(state.uuid, document["uuid"].as_str().unwrap());
        assert_eq!(state.core_directory, document["coreDirectory"].as_str().unwrap());
        assert!(serde_json::to_value(&state.feed).unwrap() == document["feed"]);
        assert!(serde_json::to_value(&state.profile).unwrap() == document["profile"]);
        assert_eq!(fs::read(&path).unwrap(), ciphertext, "loading must not rewrite the user's state");

        save(&path, &state).unwrap();
        let plaintext = Zeroizing::new(unprotect(&path, &fs::read(&path).unwrap()).unwrap());
        let canonical: ClientState = profile::parse_strict(&plaintext, MAXIMUM_STORED_BYTES).unwrap();
        assert_eq!(canonical.uuid, state.uuid);
        assert!(serde_json::to_value(&canonical.feed).unwrap() == serde_json::to_value(&state.feed).unwrap());
        assert!(serde_json::to_value(&canonical.profile).unwrap() == serde_json::to_value(&state.profile).unwrap());
    }

    #[test]
    fn connection_preferences_and_account_cache_survive_dpapi_but_cannot_cross_accounts() {
        use sha2::{Digest, Sha256};
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.bin");
        let fixture: Value = serde_json::from_slice(include_bytes!("../tests/fixtures/protocol-dotnet.json")).unwrap();
        let mut state = ClientState::default();
        state.feed = Some(serde_json::from_value(fixture["invitation"]["feed"].clone()).unwrap());
        state.profile = Some(serde_json::from_value(fixture["profile"].clone()).unwrap());
        state.uuid = "11111111-2222-4333-8444-555555555555".into();
        state.preferences.fingerprint = Some("firefox".into());
        state.preferences.domain_suffixes = vec!["example.org".into()];
        state.preferences.applications = vec!["ChatGPT.exe".into()];
        state.account = Some(AccountCache {
            profile_id: state.profile.as_ref().unwrap().profile_id.clone(),
            snapshot: account::AccountSnapshot {
                format: 1, generated_at: chrono::Utc::now().timestamp(),
                subject: hex::encode(Sha256::digest(state.uuid.as_bytes())),
                enabled: true, expires_at: None, activation_pending: false,
                traffic_limit_bytes: Some(1024), upload_bytes: 100, download_bytes: 200, inbounds: Vec::new(),
            },
        });
        save(&path, &state).unwrap();
        let before = fs::read(&path).unwrap();
        let restored = load(&path).unwrap().unwrap();
        assert!(restored.preferences == state.preferences);
        assert_eq!(restored.account.as_ref().unwrap().snapshot.traffic_limit_bytes, Some(1024));
        assert_eq!(restored.account.as_ref().unwrap().snapshot.upload_bytes, 100);
        state.uuid = "22222222-3333-4444-8555-666666666666".into();
        assert!(save(&path, &state).is_err(), "another UUID must not inherit cached account credentials");
        assert_eq!(fs::read(&path).unwrap(), before, "rejection must preserve protected state");
    }

    #[test]
    fn legacy_state_does_not_accept_unknown_fields_wrong_types_or_duplicates() {
        let directory = tempfile::tempdir().unwrap();
        let original = serde_json::to_string(&legacy_document()).unwrap();
        for (index, invalid) in [
            original.replace("\"includePrereleases\":true", "\"futurePreference\":true"),
            original.replace("\"includePrereleases\":true", "\"includePrereleases\":\"true\""),
            original.replace("\"includePrereleases\":true", "\"includePrereleases\":true,\"includePrereleases\":false"),
        ].iter().enumerate() {
            let path = directory.path().join(format!("invalid-{index}.bin"));
            let ciphertext = protect(&path, invalid.as_bytes()).unwrap();
            fs::write(&path, &ciphertext).unwrap();
            assert!(load(&path).is_err(), "invalid protected state must remain rejected");
            assert_eq!(fs::read(&path).unwrap(), ciphertext, "rejection must not overwrite the original");
        }
    }
}
