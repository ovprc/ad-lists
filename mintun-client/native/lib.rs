pub mod account;
pub mod config;
pub mod controller;
pub mod models;
pub mod paths;
pub mod profile;
pub mod preferences;
pub mod storage;
pub mod updates;
pub mod version;

#[cfg(not(target_os = "android"))]
pub(crate) mod core_trust;

#[cfg(not(target_os = "android"))]
pub mod helper;
#[cfg(not(target_os = "android"))]
pub mod runtime;
#[cfg(target_os = "android")]
pub mod android;

#[cfg(all(feature = "ui", not(target_os = "android")))]
mod instance;

#[cfg(feature = "ui")]
mod ui_bridge;

#[cfg(feature = "ui")]
pub fn run() -> anyhow::Result<()> {
    ui_bridge::run()
}

#[cfg(all(target_os = "android", feature = "ui"))]
#[unsafe(no_mangle)]
fn android_main(app: slint::android::AndroidApp) {
    let initialized = android::initialize(app);
    if let Err(error) = initialized.and_then(|_| run()) {
        android::report_startup_error(&error.to_string());
    }
}
