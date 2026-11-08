#[cfg(target_os = "linux")]

use std::{io::Write, net::TcpListener, os::{fd::AsRawFd, unix::{ffi::OsStrExt, fs::PermissionsExt}}, process::{Command, Stdio}, sync::mpsc, thread, time::Duration};

#[cfg(target_os = "linux")]
#[test]
#[ignore = "Requires root in a disposable Linux guest and MINTUN_TEST_HELPER_EXECUTABLE; never run on the host VPN"]
fn failed_helper_authentication_exits_before_caller_eof() {
    assert_eq!(unsafe { libc::geteuid() }, 0, "isolated guest root only");
    let executable = std::env::var_os("MINTUN_TEST_HELPER_EXECUTABLE").expect("set the actual native helper executable");
    let directory = tempfile::tempdir().unwrap();
    let core = directory.path().join("sing-box");
    std::fs::write(&core, b"unauthenticated code must never execute").unwrap();
    std::fs::set_permissions(&core, std::fs::Permissions::from_mode(0o700)).unwrap();
    for path in [directory.path(), core.as_path()] {
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::chown(name.as_ptr(), 1000, 1000) }, 0);
    }
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let mut ready = libc::pollfd { fd: listener.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        assert_eq!(unsafe { libc::poll(&mut ready, 1, 20_000) }, 1, "helper did not attempt the supplied route");
        let (connection, _) = listener.accept().unwrap();
        drop(connection); // Force authentication transport failure; no request can reach the Internet.
    });
    let request = serde_json::to_vec(&serde_json::json!({
        "directory": directory.path(), "version": format!("0.0.0-test-{}", uuid::Uuid::new_v4().simple()),
        "action": "verify", "proxy": {"port": port, "username": "synthetic", "password": "synthetic"}, "json": ""
    })).unwrap();
    let mut child = Command::new(executable).arg("--mintun-core-helper").env("PKEXEC_UID", "1000")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
    let pid = child.id();
    let mut input = child.stdin.take().unwrap();
    input.write_all(&(request.len() as u32).to_be_bytes()).unwrap();
    input.write_all(&request).unwrap(); input.flush().unwrap();
    let (send, receive) = mpsc::channel();
    let waiter = thread::spawn(move || send.send(child.wait().unwrap()).unwrap());
    let ended = receive.recv_timeout(Duration::from_secs(20));
    drop(input); // Keep caller input open until after observing helper termination.
    if ended.is_err() && receive.recv_timeout(Duration::from_secs(5)).is_err() {
        unsafe { libc::kill(pid as i32, libc::SIGKILL); }
    }
    waiter.join().unwrap(); server.join().unwrap();
    assert!(ended.is_ok(), "failed helper waited for caller EOF instead of reporting its failure");
    assert!(!ended.unwrap().success(), "authentication failure unexpectedly succeeded");
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "Requires root in a disposable Linux guest and MINTUN_TEST_HELPER_EXECUTABLE; never run on the host VPN"]
fn fifo_core_component_is_rejected_before_eof_and_after_caller_exit() {
    use std::io::Read;
    assert_eq!(unsafe { libc::geteuid() }, 0, "isolated guest root only");
    let executable = std::env::var_os("MINTUN_TEST_HELPER_EXECUTABLE").expect("set the actual native helper executable");
    let directory = tempfile::tempdir().unwrap();
    let fifo = directory.path().join("extra.so");
    let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    for path in [directory.path(), fifo.as_path()] {
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::chown(name.as_ptr(), 1000, 1000) }, 0);
    }
    let request = serde_json::to_vec(&serde_json::json!({
        "directory": directory.path(), "version": "1.15.0-alpha.13",
        "action": "verify", "proxy": null, "json": ""
    })).unwrap();
    for caller_eof in [false, true] {
        let mut child = Command::new(&executable).arg("--mintun-core-helper").env("PKEXEC_UID", "1000")
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        let mut input = child.stdin.take().unwrap();
        input.write_all(&(request.len() as u32).to_be_bytes()).unwrap();
        input.write_all(&request).unwrap(); input.flush().unwrap();
        // Both a live caller and an exited caller must observe prompt rejection.
        let input = if caller_eof { drop(input); None } else { Some(input) };
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let ended = loop {
            if let Some(status) = child.try_wait().unwrap() { break Some(status); }
            if std::time::Instant::now() >= deadline { break None; }
            thread::sleep(Duration::from_millis(10));
        };
        // Own and reap the child even against the old synchronously blocked helper.
        if ended.is_none() { child.kill().unwrap(); }
        let status = child.wait().unwrap();
        drop(input);
        let mut output = Vec::new(); child.stdout.take().unwrap().read_to_end(&mut output).unwrap();
        let mut error = String::new(); child.stderr.take().unwrap().read_to_string(&mut error).unwrap();
        assert!(ended.is_some(), "FIFO component blocked helper rejection (caller EOF: {caller_eof})");
        assert!(!status.success(), "FIFO core component was accepted");
        assert_eq!(output.first(), Some(&0), "rejected request must return a startup error frame");
        let size = u32::from_be_bytes(output[1..5].try_into().unwrap()) as usize;
        assert!((1..=4096).contains(&size));
        assert_eq!(output.len(), size + 5);
        assert!(std::str::from_utf8(&output[5..]).is_ok());
    }
}

#[cfg(all(windows, feature = "ui"))]
#[test]
fn internal_helper_failure_exits_without_a_modal_gui_dialog() {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::{Foundation::WAIT_OBJECT_0, System::Threading::WaitForSingleObject};
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_MinTunClient"))
        .args(["--mintun-core-helper", "invalid-pipe-name"])
        .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
        .spawn().unwrap();
    let exited = unsafe { WaitForSingleObject(child.as_raw_handle().cast(), 10_000) };
    if exited != WAIT_OBJECT_0 { child.kill().unwrap(); }
    let status = child.wait().unwrap();
    assert_eq!(exited, WAIT_OBJECT_0, "internal helper failure blocked instead of closing its transport");
    assert!(!status.success(), "malformed internal helper request unexpectedly succeeded");
}
