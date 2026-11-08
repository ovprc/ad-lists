use anyhow::{Result, anyhow, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs::{self, OpenOptions}, io::Read, path::{Path, PathBuf}};
use tokio_util::sync::CancellationToken;
use crate::{models::ProxyEndpoint, updates::{self, UpdateClient}, version};

const BUNDLED_VERSION: &str = "1.15.0-alpha.13";
const EMBEDDED: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/trusted-core.json"));
const MAX_RECEIPT: u64 = 64 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TrustedCore {
    pub(crate) version: String,
    pub(crate) os: String,
    pub(crate) arch: String,
    pub(crate) asset_sha256: String,
    #[serde(deserialize_with = "unique_files")]
    pub(crate) files: BTreeMap<String, String>,
}

fn unique_files<'de, D: serde::Deserializer<'de>>(deserializer: D) -> std::result::Result<BTreeMap<String, String>, D::Error> {
    struct Files;
    impl<'de> serde::de::Visitor<'de> for Files {
        type Value = BTreeMap<String, String>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result { formatter.write_str("unique executable filenames and SHA256 digests") }
        fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> std::result::Result<Self::Value, A::Error> {
            let mut files = BTreeMap::new();
            while let Some((name, digest)) = map.next_entry::<String, String>()? {
                if files.len() >= 256 || files.insert(name, digest).is_some() {
                    return Err(serde::de::Error::custom("duplicate or excessive trusted executable files"));
                }
            }
            Ok(files)
        }
    }
    deserializer.deserialize_map(Files)
}

fn valid_hash(hash: &str) -> bool {
    hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}


impl TrustedCore {
    fn validate(&self, selected: &str) -> Result<()> {
        ensure!(version::normalize(selected)? == selected && self.version == selected, "Trusted core version mismatch");
        ensure!(self.os == std::env::consts::OS && self.arch == std::env::consts::ARCH, "Trusted core platform mismatch");
        ensure!(valid_hash(&self.asset_sha256) && !self.files.is_empty() && self.files.len() <= 256, "Invalid trusted core asset digest or file count");
        ensure!(self.files.contains_key(if cfg!(windows) { "sing-box.exe" } else { "sing-box" }), "Trusted core lacks its executable");
        let mut names = std::collections::HashSet::new();
        for (name, hash) in &self.files {
            ensure!(updates::executable_file(name) && valid_hash(hash) && names.insert(name.to_ascii_lowercase()), "Invalid or duplicate trusted executable component");
        }
        Ok(())
    }
}

fn embedded_from(bytes: &[u8], selected: &str) -> Result<Option<TrustedCore>> {
    ensure!(version::normalize(selected)? == selected, "Core version must be normalized");
    let embedded: Option<TrustedCore> = serde_json::from_slice(bytes)?;
    if let Some(trusted) = embedded {
        trusted.validate(&trusted.version)?;
        if trusted.version == selected { return Ok(Some(trusted)); }
    }
    ensure!(selected != BUNDLED_VERSION, "Не подготовлен доверенный bundled core: соберите MinTun через scripts/build-desktop.ps1 с официальным manifest");
    Ok(None)
}

fn reject_link(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    ensure!(!metadata.file_type().is_symlink(), "Core trust paths must not be symbolic links: {}", path.display());
    #[cfg(windows)] {
        use std::os::windows::fs::MetadataExt;
        ensure!(metadata.file_attributes() & 0x400 == 0, "Core trust paths must not be reparse points");
    }
    Ok(())
}

fn executable_hashes(directory: &Path) -> Result<BTreeMap<String, String>> {
    let metadata = fs::symlink_metadata(directory)?;
    reject_link(directory, &metadata)?;
    ensure!(metadata.is_dir(), "Core bundle must be a directory");
    let mut files = BTreeMap::new();
    let mut names = std::collections::HashSet::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        reject_link(&path, &metadata)?;
        let name = entry.file_name().into_string().map_err(|_| anyhow!("Non-UTF8 core filename"))?;
        if metadata.is_dir() {
            ensure!(name == "runtime", "Unexpected core bundle subdirectory");
            continue;
        }
        ensure!(metadata.is_file(), "Core bundle contains a special file");
        // Never ignore an executable-looking name merely because it violates
        // the safe filename grammar (e.g. an NTFS alternate data stream).
        let lower = name.to_ascii_lowercase();
        let looks_executable = lower == "sing-box" || [".exe", ".dll", ".so", ".dylib", ".so."].iter().any(|ext| lower.contains(ext));
        if !looks_executable { continue; }
        ensure!(updates::executable_file(&name) && names.insert(lower), "Unsafe or duplicate executable component");
        ensure!(metadata.len() > 0 && metadata.len() <= 256 * 1024 * 1024 && files.len() < 256, "Invalid executable component size or count");
        let mut options = OpenOptions::new(); options.read(true);
        #[cfg(any(target_os = "linux", target_os = "macos"))] {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        #[cfg(windows)] {
            use std::os::windows::fs::OpenOptionsExt;
            options.custom_flags(0x00200000); // FILE_FLAG_OPEN_REPARSE_POINT
        }
        let mut file = options.open(&path)?;
        reject_link(&path, &file.metadata()?)?;
        let mut hash = Sha256::new(); let mut buffer = [0u8; 65536]; let mut length = 0;
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 { break; }
            length += count as u64;
            ensure!(length <= metadata.len(), "Executable changed while authenticating");
            hash.update(&buffer[..count]);
        }
        ensure!(length == metadata.len(), "Executable changed while authenticating");
        files.insert(name, hex::encode(hash.finalize()));
    }
    Ok(files)
}

pub(crate) fn verify_directory(directory: &Path, trusted: &TrustedCore) -> Result<()> {
    trusted.validate(&trusted.version)?;
    ensure!(executable_hashes(directory)? == trusted.files, "Core executable file set or SHA256 differs from the authenticated official bundle");
    Ok(())
}

pub(crate) async fn authenticate(selected: &str, proxy: Option<&ProxyEndpoint>, cancel: &CancellationToken) -> Result<TrustedCore> {
    ensure!(!cancel.is_cancelled(), "Operation cancelled");
    if let Some(trusted) = embedded_from(EMBEDDED, selected)? { return Ok(trusted); }
    let root = protected_root()?;
    let receipt = root.join(receipt_name(selected));
    if let Some(trusted) = read_receipt(&receipt, selected)? { return Ok(trusted); }
    let client = UpdateClient::new(proxy)?;
    let release = updates::official_core_release(&client, selected, cancel).await?;
    let staging = private_staging()?;
    let bundle = updates::extract_official_core(&client, &release, staging.path(), cancel).await?;
    let hash_cancel = cancel.child_token();
    let _guard = hash_cancel.clone().drop_guard();
    // Keep transport EOF/cancellation observable while hashing large binaries.
    let files = tokio::task::spawn_blocking(move || {
        ensure!(!hash_cancel.is_cancelled(), "Operation cancelled");
        let files = executable_hashes(&bundle)?;
        ensure!(!hash_cancel.is_cancelled(), "Operation cancelled");
        Ok::<_, anyhow::Error>(files)
    }).await??;
    let trusted = TrustedCore {
        version: selected.into(), os: std::env::consts::OS.into(), arch: std::env::consts::ARCH.into(),
        asset_sha256: release.sha256, files,
    };
    trusted.validate(selected)?;
    let bytes = serde_json::to_vec(&trusted)?;
    ensure!(bytes.len() as u64 <= MAX_RECEIPT, "Trusted core receipt exceeds size limit");
    validate_protected(&root, true)?;
    // No receipt is committed by a cancelled or disconnected verification.
    ensure!(!cancel.is_cancelled(), "Operation cancelled");
    #[cfg(not(windows))] crate::storage::atomic_write(&receipt, &bytes)?;
    #[cfg(windows)] windows::publish_receipt(&receipt, &bytes, cancel)?;
    validate_protected(&receipt, false)?;
    Ok(trusted)
}

fn receipt_name(selected: &str) -> String {
    format!("{selected}-{}-{}.json", std::env::consts::OS, std::env::consts::ARCH)
}

fn read_receipt(path: &Path, selected: &str) -> Result<Option<TrustedCore>> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()), Ok(_) => {}
    }
    validate_protected(path, false)?;
    let mut options = OpenOptions::new(); options.read(true);
    #[cfg(any(target_os = "linux", target_os = "macos"))] {
        use std::os::unix::fs::OpenOptionsExt; options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    ensure!(file.metadata()?.len() <= MAX_RECEIPT, "Trusted core receipt exceeds size limit");
    let mut bytes = Vec::new(); file.take(MAX_RECEIPT + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= MAX_RECEIPT, "Trusted core receipt exceeds size limit");
    let trusted: TrustedCore = serde_json::from_slice(&bytes)?;
    trusted.validate(selected)?;
    Ok(Some(trusted))
}

pub(crate) struct PrivateStaging { path: PathBuf }
impl PrivateStaging { pub(crate) fn path(&self) -> &Path { &self.path } }
impl Drop for PrivateStaging {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.path); }
}

pub(crate) fn private_staging() -> Result<PrivateStaging> {
    let path = protected_root()?.join(format!(".verify-{}", uuid::Uuid::new_v4().simple()));
    #[cfg(any(target_os = "linux", target_os = "macos"))] {
        use std::os::unix::fs::DirBuilderExt;
        ensure!(unsafe { libc::geteuid() } == 0, "Private core staging requires the elevated helper");
        fs::DirBuilder::new().mode(0o700).create(&path)?;
    }
    // Supply owner/DACL to the create operation, never retrofit permissions on
    // a caller-owned temporary directory after an attacker could open a handle.
    #[cfg(windows)] windows::create_directory(&path)?;
    let directory = PrivateStaging { path };
    validate_protected(directory.path(), true)?;
    Ok(directory)
}

fn protected_root() -> Result<PathBuf> {
    #[cfg(target_os = "linux")] let root = PathBuf::from("/var/lib/mintun/core-trust");
    #[cfg(target_os = "macos")] let root = PathBuf::from("/Library/Application Support/MinTun/core-trust");
    #[cfg(windows)] let root = windows::program_data()?.join("MinTunClient").join("core-trust");
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))] {
        anyhow::bail!("This platform uses an application-embedded core")
    }
    #[cfg(any(windows, target_os = "linux", target_os = "macos"))] {
        create_protected_directory(&root)?;
        validate_protected(&root, true)?;
        Ok(root)
    }
}

fn create_protected_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => return validate_protected(path, true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
        Err(error) => return Err(error.into()),
    }
    let parent = path.parent().ok_or_else(|| anyhow!("Missing protected directory parent"))?;
    if !parent.try_exists()? { create_protected_directory(parent)?; }
    validate_ancestors(parent)?;
    #[cfg(any(target_os = "linux", target_os = "macos"))] {
        use std::os::unix::fs::DirBuilderExt;
        ensure!(unsafe { libc::geteuid() } == 0, "Core trust preparation requires the elevated helper");
        match fs::DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => {}, Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {},
            Err(error) => return Err(error.into()),
        }
    }
    #[cfg(windows)] windows::create_directory(path)?;
    validate_protected(path, true)
}

fn validate_ancestors(path: &Path) -> Result<()> {
    for ancestor in path.ancestors() {
        if ancestor.as_os_str().is_empty() { continue; }
        let metadata = fs::symlink_metadata(ancestor)?;
        reject_link(ancestor, &metadata)?;
        ensure!(metadata.is_dir(), "Core trust ancestor is not a directory");
        #[cfg(any(target_os = "linux", target_os = "macos"))] {
            use std::os::unix::fs::MetadataExt;
            ensure!(metadata.uid() == 0 && metadata.mode() & 0o022 == 0, "Core trust ancestor is not root-owned and protected");
        }
        #[cfg(windows)] windows::validate_acl(ancestor, false)?;
    }
    Ok(())
}

fn validate_protected(path: &Path, directory: bool) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    reject_link(path, &metadata)?;
    ensure!(if directory { metadata.is_dir() } else { metadata.is_file() }, "Invalid protected core trust path type");
    if let Some(parent) = path.parent() { validate_ancestors(parent)?; }
    #[cfg(any(target_os = "linux", target_os = "macos"))] {
        use std::os::unix::fs::MetadataExt;
        ensure!(metadata.uid() == 0 && metadata.mode() & 0o7777 == if directory { 0o700 } else { 0o600 }, "Core trust cache must be root-owned and mode 0700/0600");
        ensure!(directory || metadata.nlink() == 1, "Core trust receipt must not be hard-linked");
    }
    #[cfg(windows)] windows::validate_acl(path, true)?;
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))] anyhow::bail!("Unsupported core trust cache platform");
    Ok(())
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::{ffi::c_void, io::Write, os::windows::{ffi::{OsStrExt, OsStringExt}, io::FromRawHandle}, ptr};
    use windows_sys::Win32::{
        Foundation::{LocalFree, INVALID_HANDLE_VALUE},
        Security::{self, Authorization, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, SECURITY_ATTRIBUTES},
        Storage::FileSystem::{CreateDirectoryW, CreateFileW, MoveFileExW},
        UI::Shell::{SHGetKnownFolderPath, FOLDERID_ProgramData},
    };

    struct Local(*mut c_void);
    impl Drop for Local { fn drop(&mut self) { if !self.0.is_null() { unsafe { LocalFree(self.0); } } } }
    fn wide(path: &Path) -> Result<Vec<u16>> {
        let mut value: Vec<u16> = path.as_os_str().encode_wide().collect();
        ensure!(!value.contains(&0), "Invalid protected core trust path");
        value.push(0); Ok(value)
    }
    fn descriptor() -> Result<Local> {
        // Explicit protected inheritable grants ensure even temporary receipts
        // are private before their final DACL is marked protected.
        let sddl: Vec<u16> = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)\0".encode_utf16().collect();
        let mut descriptor = Local(ptr::null_mut());
        ensure!(unsafe { Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), 1, &mut descriptor.0, ptr::null_mut()) } != 0, "Cannot construct protected core trust DACL");
        Ok(descriptor)
    }
    pub(super) fn program_data() -> Result<PathBuf> {
        #[link(name = "ole32")]
        unsafe extern "system" { fn CoTaskMemFree(memory: *const c_void); }
        let mut pointer = ptr::null_mut();
        // KF_FLAG_DEFAULT_PATH avoids per-user KnownFolder redirection; never
        // obtain this privileged directory from PROGRAMDATA or another env var.
        let result = unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramData, 0x400, ptr::null_mut(), &mut pointer) };
        ensure!(result >= 0 && !pointer.is_null(), "Cannot resolve OS ProgramData KnownFolder");
        struct KnownFolder(*mut u16);
        impl Drop for KnownFolder { fn drop(&mut self) { unsafe { CoTaskMemFree(self.0.cast()); } } }
        let folder = KnownFolder(pointer);
        let mut length = 0;
        while length < 32768 && unsafe { *folder.0.add(length) } != 0 { length += 1; }
        ensure!(length < 32768, "Invalid OS ProgramData path");
        let path = PathBuf::from(std::ffi::OsString::from_wide(unsafe { std::slice::from_raw_parts(folder.0, length) }));
        ensure!(path.is_absolute(), "ProgramData KnownFolder must be absolute");
        validate_ancestors(&path)?;
        Ok(path)
    }
    pub(super) fn create_directory(path: &Path) -> Result<()> {
        let descriptor = descriptor()?;
        let attributes = SECURITY_ATTRIBUTES { nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: descriptor.0, bInheritHandle: 0 };
        let name = wide(path)?;
        if unsafe { CreateDirectoryW(name.as_ptr(), &attributes) } == 0 {
            let error = std::io::Error::last_os_error();
            return Err(anyhow!("Cannot create protected core trust directory: {error}"));
        }
        Ok(())
    }
    pub(super) fn publish_receipt(path: &Path, bytes: &[u8], cancel: &CancellationToken) -> Result<()> {
        let parent = path.parent().ok_or_else(|| anyhow!("Missing receipt directory"))?;
        let temporary = parent.join(format!(".receipt-{}.tmp", uuid::Uuid::new_v4().simple()));
        struct RemoveTemporary(PathBuf);
        impl Drop for RemoveTemporary { fn drop(&mut self) { let _ = fs::remove_file(&self.0); } }
        let _cleanup = RemoveTemporary(temporary.clone());
        let descriptor = descriptor()?;
        let attributes = SECURITY_ATTRIBUTES { nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: descriptor.0, bInheritHandle: 0 };
        let source = wide(&temporary)?; let destination = wide(path)?;
        // A plain OpenOptions temporary would initially belong to the token's
        // default owner. Set BA/SY owner and protected DACL at CREATE_NEW, before
        // any receipt bytes exist or its predictable final pathname is visible.
        let handle = unsafe { CreateFileW(source.as_ptr(), 0x40000000, 0, &attributes, 1, 0x00200080, ptr::null_mut()) };
        ensure!(handle != INVALID_HANDLE_VALUE, "Cannot create protected receipt temporary");
        let mut file = unsafe { fs::File::from_raw_handle(handle) };
        file.write_all(bytes)?; file.sync_all()?; drop(file);
        validate_protected(&temporary, false)?;
        ensure!(!cancel.is_cancelled(), "Operation cancelled");
        ensure!(unsafe { MoveFileExW(source.as_ptr(), destination.as_ptr(), 0x9) } != 0, "Cannot atomically publish protected receipt");
        Ok(())
    }
    fn privileged(sid: Security::PSID) -> bool {
        !sid.is_null() && unsafe {
            Security::IsValidSid(sid) != 0 && (Security::IsWellKnownSid(sid, Security::WinLocalSystemSid) != 0
                || Security::IsWellKnownSid(sid, Security::WinBuiltinAdministratorsSid) != 0)
        }
    }
    pub(super) fn validate_acl(path: &Path, private: bool) -> Result<()> {
        let name = wide(path)?;
        let mut owner = ptr::null_mut(); let mut dacl: *mut ACL = ptr::null_mut();
        let mut descriptor = Local(ptr::null_mut());
        ensure!(unsafe { Authorization::GetNamedSecurityInfoW(name.as_ptr(), 1, 5, &mut owner, ptr::null_mut(), &mut dacl, ptr::null_mut(), &mut descriptor.0) } == 0, "Cannot inspect core trust security descriptor");
        ensure!(!descriptor.0.is_null() && !owner.is_null() && !dacl.is_null(), "Core trust requires an owner and non-null DACL");
        // Windows' service-owned volume ancestors may belong to TrustedInstaller,
        // but the cache, receipts and staging themselves must belong to BA/SY.
        let installer: Vec<u16> = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464\0".encode_utf16().collect();
        let mut installer_sid = Local(ptr::null_mut());
        ensure!(unsafe { Authorization::ConvertStringSidToSidW(installer.as_ptr(), &mut installer_sid.0) } != 0, "Cannot resolve trusted Windows service SID");
        let trusted = |sid| privileged(sid) || (!private && unsafe { Security::EqualSid(sid, installer_sid.0) } != 0);
        ensure!(trusted(owner), "Core trust path has an unprivileged owner");
        let mut control = 0u16; let mut revision = 0;
        ensure!(unsafe { Security::GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) } != 0, "Cannot inspect core trust DACL control");
        ensure!(!private || control & Security::SE_DACL_PROTECTED != 0, "Core trust DACL must be protected from inheritance");
        let mut system_grant = false; let mut admin_grant = false;
        for index in 0..unsafe { (*dacl).AceCount } as u32 {
            let mut pointer = ptr::null_mut();
            ensure!(unsafe { Security::GetAce(dacl, index, &mut pointer) } != 0 && !pointer.is_null(), "Invalid core trust DACL entry");
            let header = unsafe { &*pointer.cast::<ACE_HEADER>() };
            if header.AceFlags & 0x08 != 0 { continue; } // INHERIT_ONLY_ACE
            ensure!(matches!(header.AceType, 0 | 1), "Unsupported core trust DACL entry type");
            if header.AceType == 1 { continue; } // A deny cannot grant access.
            ensure!(header.AceSize as usize >= std::mem::size_of::<ACCESS_ALLOWED_ACE>(), "Truncated core trust DACL entry");
            let ace = unsafe { &*pointer.cast::<ACCESS_ALLOWED_ACE>() };
            let sid = (&ace.SidStart as *const u32).cast_mut().cast();
            ensure!(unsafe { Security::IsValidSid(sid) } != 0, "Invalid core trust DACL SID");
            if private {
                ensure!(privileged(sid), "Core trust DACL grants access outside SYSTEM/Administrators");
                if ace.Mask & 0x1f01ff == 0x1f01ff {
                    system_grant |= unsafe { Security::IsWellKnownSid(sid, Security::WinLocalSystemSid) } != 0;
                    admin_grant |= unsafe { Security::IsWellKnownSid(sid, Security::WinBuiltinAdministratorsSid) } != 0;
                }
            } else if !trusted(sid) {
                // Ancestors may allow users to CREATE a child (ProgramData).
                // They must not let them replace an existing trusted namespace,
                // rewrite its owner/DACL, or delete the protected child.
                ensure!(ace.Mask & (0x10000000 | 0x40000000 | 0x000d0040) == 0, "Core trust ancestor permits unprivileged replacement");
            }
        }
        ensure!(!private || (system_grant && admin_grant), "Core trust DACL lacks full SYSTEM/Administrators access");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(directory: &Path) -> TrustedCore {
        let name = if cfg!(windows) { "sing-box.exe" } else { "sing-box" };
        std::fs::write(directory.join(name), b"abc").unwrap();
        TrustedCore {
            version: "1.2.3".into(), os: std::env::consts::OS.into(), arch: std::env::consts::ARCH.into(),
            asset_sha256: "0".repeat(64),
            files: BTreeMap::from([(name.into(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into())]),
        }
    }

    #[test]
    fn rejects_mutated_missing_and_extra_executable_components() {
        let directory = tempfile::tempdir().unwrap();
        let trusted = fixture(directory.path());
        verify_directory(directory.path(), &trusted).unwrap();
        let main = directory.path().join(trusted.files.keys().next().unwrap());
        std::fs::write(&main, b"abd").unwrap();
        assert!(verify_directory(directory.path(), &trusted).is_err());
        std::fs::write(&main, b"abc").unwrap();
        for extra in ["extra.dll", "extra.exe", "extra.so", "extra.so.1", "extra.dylib"] {
            let path = directory.path().join(extra);
            std::fs::write(&path, b"abc").unwrap();
            assert!(verify_directory(directory.path(), &trusted).is_err(), "{extra}");
            std::fs::remove_file(path).unwrap();
        }
        std::fs::remove_file(main).unwrap();
        assert!(verify_directory(directory.path(), &trusted).is_err());
    }

    #[test]
    fn embedded_match_is_offline_and_exact() {
        let directory = tempfile::tempdir().unwrap();
        let trusted = fixture(directory.path());
        let bytes = serde_json::to_vec(&trusted).unwrap();
        let embedded = embedded_from(&bytes, "1.2.3").unwrap().unwrap();
        verify_directory(directory.path(), &embedded).unwrap();
        assert!(embedded_from(&bytes, "1.2.4").unwrap().is_none());
        assert!(embedded_from(&bytes, "v1.2.3").is_err());
        assert!(embedded_from(b"null", BUNDLED_VERSION).is_err());
        assert!(embedded_from(b"null", "1.2.3").unwrap().is_none());
    }

    #[test]
    fn strict_manifest_rejects_duplicate_names_unknown_fields_and_platform() {
        let directory = tempfile::tempdir().unwrap();
        let trusted = fixture(directory.path());
        let mut value = serde_json::to_value(&trusted).unwrap();
        value["caller_trusted"] = true.into();
        assert!(serde_json::from_value::<TrustedCore>(value).is_err());
        let mut wrong = trusted.clone(); wrong.os = "other".into();
        assert!(wrong.validate("1.2.3").is_err());
        let mut wrong = trusted.clone(); wrong.arch = "other".into();
        assert!(wrong.validate("1.2.3").is_err());
        let bytes = serde_json::to_string(&trusted).unwrap();
        let key = trusted.files.keys().next().unwrap();
        let duplicate = bytes.replace(&format!("\"{key}\":"), &format!("\"{key}\":\"{}\",\"{key}\":", "0".repeat(64)));
        assert!(serde_json::from_str::<TrustedCore>(&duplicate).is_err());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn rejects_symlinked_components_and_user_counterfeit_receipt() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let directory = tempfile::tempdir().unwrap();
        let trusted = fixture(directory.path());
        let main = directory.path().join(trusted.files.keys().next().unwrap());
        let original = directory.path().join("original");
        std::fs::rename(&main, &original).unwrap();
        symlink(&original, &main).unwrap();
        assert!(verify_directory(directory.path(), &trusted).is_err());
        let receipt = directory.path().join("receipt.json");
        std::fs::write(&receipt, serde_json::to_vec(&trusted).unwrap()).unwrap();
        std::fs::set_permissions(&receipt, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_receipt(&receipt, "1.2.3").is_err());
        std::fs::set_permissions(&receipt, std::fs::Permissions::from_mode(0o600)).unwrap();
        if unsafe { libc::geteuid() } != 0 {
            assert!(read_receipt(&receipt, "1.2.3").is_err());
        }
    }

    #[cfg(windows)]
    #[test]
    fn rejects_user_counterfeit_receipt() {
        let directory = tempfile::tempdir().unwrap();
        let trusted = fixture(directory.path());
        let receipt = directory.path().join("receipt.json");
        std::fs::write(&receipt, serde_json::to_vec(&trusted).unwrap()).unwrap();
        assert!(read_receipt(&receipt, "1.2.3").is_err());
    }

    #[test]
    fn dependency_mutation_is_rejected_but_private_runtime_is_not_code() {
        let directory = tempfile::tempdir().unwrap();
        let mut trusted = fixture(directory.path());
        trusted.files.insert("dependency.dll".into(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into());
        let dependency = directory.path().join("dependency.dll");
        std::fs::write(&dependency, b"abc").unwrap();
        std::fs::create_dir(directory.path().join("runtime")).unwrap();
        std::fs::write(directory.path().join("runtime/cache.db"), b"not executable trust data").unwrap();
        verify_directory(directory.path(), &trusted).unwrap();
        std::fs::write(&dependency, b"abd").unwrap();
        assert!(verify_directory(directory.path(), &trusted).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "Requires root in a disposable Linux guest; creates a protected /var/lib/mintun/core-trust staging directory"]
    fn root_staging_and_receipt_reject_wrong_modes_and_owner() {
        use std::os::unix::{ffi::OsStrExt, fs::{MetadataExt, PermissionsExt}};
        assert_eq!(unsafe { libc::geteuid() }, 0, "run only as isolated guest root");
        let directory = private_staging().unwrap();
        let metadata = std::fs::symlink_metadata(directory.path()).unwrap();
        assert_eq!(metadata.uid(), 0);
        assert_eq!(metadata.mode() & 0o777, 0o700);
        let trusted = fixture(directory.path());
        let receipt = directory.path().join("receipt.json");
        crate::storage::atomic_write(&receipt, &serde_json::to_vec(&trusted).unwrap()).unwrap();
        assert_eq!(read_receipt(&receipt, "1.2.3").unwrap().unwrap().files, trusted.files);
        std::fs::set_permissions(&receipt, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_receipt(&receipt, "1.2.3").is_err());
        std::fs::set_permissions(&receipt, std::fs::Permissions::from_mode(0o600)).unwrap();
        let name = std::ffi::CString::new(receipt.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::chown(name.as_ptr(), 65534, 65534) }, 0);
        assert!(read_receipt(&receipt, "1.2.3").is_err());
    }

    #[tokio::test]
    #[ignore = "Requires isolated elevated guest and official HTTPS access; never run against the host VPN"]
    async fn official_receipt_is_protected_and_reusable() {
        let version = std::env::var("MINTUN_TEST_TRUST_VERSION").expect("set an official non-bundled test version");
        assert_ne!(version, BUNDLED_VERSION);
        let cancel = CancellationToken::new();
        let trusted = authenticate(&version, None, &cancel).await.unwrap();
        let root = protected_root().unwrap();
        let receipt = read_receipt(&root.join(receipt_name(&version)), &version).unwrap().unwrap();
        assert_eq!(trusted.files, receipt.files);
    }
}
