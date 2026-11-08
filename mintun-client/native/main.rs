#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

fn main() {
    if let Err(error) = main_result() {
        #[cfg(target_os = "windows")]
        {
            use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK};
            if std::env::args_os().nth(1).is_some_and(|arg| matches!(arg.to_str(),
                Some("--mintun-core-helper" | "--mintun-console-hide" | "--mintun-console-stop"))) {
                // Internal helpers must exit on failure, never block their caller on a GUI dialog.
                eprintln!("MinTun helper: {error:#}");
            } else {
                let message: Vec<u16> = format!("Не удалось запустить MinTun.\n\n{error:#}")
                    .encode_utf16().chain(Some(0)).collect();
                let title: Vec<u16> = "MinTun".encode_utf16().chain(Some(0)).collect();
                unsafe { MessageBoxW(std::ptr::null_mut(), message.as_ptr(), title.as_ptr(), MB_OK | MB_ICONERROR); }
            }
        }
        #[cfg(not(target_os = "windows"))]
        eprintln!("MinTun: {error:#}");
        std::process::exit(1);
    }
}

fn main_result() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if mintun_client::helper::try_run(&args)? {
        return Ok(());
    }
    anyhow::ensure!(mintun_client::helper::needs_elevation(),
        "Запустите MinTun без прав администратора; разрешение будет запрошено для ядра");
    mintun_client::run()
}
