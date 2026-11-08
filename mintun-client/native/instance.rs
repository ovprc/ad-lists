use anyhow::Result;
#[cfg(unix)]
use anyhow::Context;
use crate::paths::Paths;

#[cfg(target_os = "windows")]
pub struct Instance {
    mutex: usize,
    event: usize,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(target_os = "windows")]
impl Instance {
    pub fn acquire(paths: &Paths, activate: impl Fn() + Send + 'static) -> Result<Option<Self>> {
        use sha2::{Digest, Sha256};
        use windows_sys::Win32::{Foundation::*, System::Threading::*};
        let root = paths.root.to_string_lossy();
        let root = root.strip_prefix(r"\\?\").unwrap_or(&root).trim_end_matches(['\\', '/']).to_uppercase();
        let suffix = hex::encode_upper(Sha256::digest(root.as_bytes()));
        let name = format!("Local\\MinTunClient-{}-{}", user_sid()?, &suffix[..16]);
        let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        let show: Vec<u16> = format!("{name}-show").encode_utf16().chain(Some(0)).collect();
        unsafe {
            let mutex = CreateMutexW(std::ptr::null(), 1, wide.as_ptr());
            anyhow::ensure!(!mutex.is_null(), "Не удалось создать блокировку экземпляра приложения");
            if GetLastError() == ERROR_ALREADY_EXISTS {
                let event = OpenEventW(EVENT_MODIFY_STATE, 0, show.as_ptr());
                if !event.is_null() { SetEvent(event); CloseHandle(event); }
                CloseHandle(mutex);
                return Ok(None);
            }
            let event = CreateEventW(std::ptr::null(), 0, 0, show.as_ptr());
            if event.is_null() {
                ReleaseMutex(mutex); CloseHandle(mutex);
                anyhow::bail!("Не удалось создать канал активации окна");
            }
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let stopped = stop.clone();
            let event_value = event as usize;
            let thread = std::thread::Builder::new().name("mintun-activation".into()).spawn(move || {
                loop {
                    let result = WaitForSingleObject(event_value as HANDLE, INFINITE);
                    if result != WAIT_OBJECT_0 || stopped.load(std::sync::atomic::Ordering::Acquire) { break; }
                    activate();
                }
            })?;
            Ok(Some(Self { mutex: mutex as usize, event: event_value, stop, thread: Some(thread) }))
        }
    }
}

#[cfg(target_os = "windows")]
impl Drop for Instance {
    fn drop(&mut self) {
        use windows_sys::Win32::{Foundation::*, System::Threading::*};
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        unsafe { SetEvent(self.event as HANDLE); }
        if let Some(thread) = self.thread.take() { let _ = thread.join(); }
        unsafe { CloseHandle(self.event as HANDLE); ReleaseMutex(self.mutex as HANDLE); CloseHandle(self.mutex as HANDLE); }
    }
}

#[cfg(target_os = "windows")]
fn user_sid() -> Result<String> {
    use windows_sys::Win32::{Foundation::*, Security::*, Security::Authorization::ConvertSidToStringSidW, System::Threading::*};
    unsafe {
        let mut token = std::ptr::null_mut();
        anyhow::ensure!(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) != 0, "Не удалось определить пользователя");
        let mut length = 0;
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut length);
        let mut bytes = vec![0u8; length as usize];
        let success = GetTokenInformation(token, TokenUser, bytes.as_mut_ptr().cast(), length, &mut length);
        CloseHandle(token);
        anyhow::ensure!(success != 0, "Не удалось прочитать идентификатор пользователя");
        let user = &*(bytes.as_ptr() as *const TOKEN_USER);
        let mut text = std::ptr::null_mut();
        anyhow::ensure!(ConvertSidToStringSidW(user.User.Sid, &mut text) != 0, "Не удалось преобразовать идентификатор пользователя");
        let mut count = 0;
        while *text.add(count) != 0 { count += 1; }
        let value = String::from_utf16_lossy(std::slice::from_raw_parts(text, count));
        LocalFree(text.cast());
        Ok(value)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub struct Instance {
    lock: std::fs::File,
    socket: std::path::PathBuf,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Instance {
    pub fn acquire(paths: &Paths, activate: impl Fn() + Send + 'static) -> Result<Option<Self>> {
        use fs2::FileExt;
        use std::os::unix::{fs::{OpenOptionsExt, PermissionsExt}, net::{UnixListener, UnixStream}};
        let socket = paths.root.join(".activation.sock");
        let lock = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).mode(0o600)
            .open(paths.root.join(".instance.lock"))?;
        match lock.try_lock_exclusive() {
            Ok(()) => (),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                let _ = UnixStream::connect(&socket);
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        }
        match std::fs::symlink_metadata(&socket) {
            Ok(metadata) => {
                use std::os::unix::fs::FileTypeExt;
                anyhow::ensure!(metadata.file_type().is_socket(), "Канал активации занят посторонним файлом");
                std::fs::remove_file(&socket)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
        let listener = UnixListener::bind(&socket).context("Не удалось создать локальный канал активации")?;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stopped = stop.clone();
        let thread = std::thread::Builder::new().name("mintun-activation".into()).spawn(move || {
            while listener.accept().is_ok() {
                if stopped.load(std::sync::atomic::Ordering::Acquire) { break; }
                activate();
            }
        })?;
        Ok(Some(Self { lock, socket, stop, thread: Some(thread) }))
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Drop for Instance {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        let _ = std::os::unix::net::UnixStream::connect(&self.socket);
        if let Some(thread) = self.thread.take() { let _ = thread.join(); }
        let _ = std::fs::remove_file(&self.socket);
        let _ = fs2::FileExt::unlock(&self.lock);
    }
}
