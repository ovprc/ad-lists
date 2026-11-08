use crate::{controller::{Command, ConnectionChoice, Controller, Event, Snapshot, WorkerHandle}, paths::Paths, preferences::{ConnectionPreferences, FINGERPRINTS}};
use anyhow::{Context, Result, ensure};
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};
use std::{path::PathBuf, sync::{Arc, Mutex}};

slint::include_modules!();

#[derive(Default)]
struct UiCache {
    uuid: Option<String>,
    versions: Vec<String>,
    inbounds: Vec<ConnectionChoice>,
    preferences: Option<ConnectionPreferences>,
}

pub fn run() -> Result<()> {
    let paths = Paths::new(data_override()?)?;
    let ui = AppWindow::new()?;
    #[cfg(target_os = "windows")]
    install_windows_repaint_handler(ui.window());
    ui.set_is_android(cfg!(target_os = "android"));
    ui.set_application_version(env!("CARGO_PKG_VERSION").into());
    let fingerprints: Vec<SharedString> = std::iter::once("Из профиля").chain(FINGERPRINTS.iter().copied()).map(SharedString::from).collect();
    ui.set_fingerprints(std::rc::Rc::new(VecModel::from(fingerprints)).into());
    let weak = ui.as_weak();
    #[cfg(not(target_os = "android"))]
    let _instance = {
        let activate = weak.clone();
        match crate::instance::Instance::acquire(&paths, move || {
            let weak = activate.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak.upgrade() { reveal(&ui); }
            });
        })? {
            Some(instance) => instance,
            None => return Ok(()),
        }
    };
    #[cfg(not(target_os = "android"))]
    let tray = if tray_available() { Some(AppTray::new()?) } else { None };
    #[cfg(not(target_os = "android"))]
    let tray_weak = tray.as_ref().map(|tray| tray.as_weak());
    let cache = Arc::new(Mutex::new(UiCache::default()));
    let worker = Controller::spawn(paths, Arc::new(move |event| {
        let weak = weak.clone();
        #[cfg(not(target_os = "android"))]
        let tray = tray_weak.clone();
        let cache = cache.clone();
        let _ = slint::invoke_from_event_loop(move || match event {
            Event::Stopped => { if weak.upgrade().is_some() { let _ = slint::quit_event_loop(); } }
            Event::RevealError => { if let Some(ui) = weak.upgrade() { ui.invoke_reveal_error(); } }
            Event::State(state) => {
                if let Some(ui) = weak.upgrade() {
                    if let Ok(mut cache) = cache.lock() { update_window(&ui, &state, &mut cache); }
                }
                #[cfg(not(target_os = "android"))]
                if let Some(tray) = tray.and_then(|tray| tray.upgrade()) {
                    tray.set_running(state.running);
                    tray.set_busy(state.busy);
                    tray.set_can_connect(state.can_connect);
                }
            }
        });
    }))?;
    connect_actions(&ui, &worker);
    #[cfg(not(target_os = "android"))]
    if let Some(tray) = &tray {
        let weak = ui.as_weak();
        tray.on_show_window(move || { if let Some(ui) = weak.upgrade() { reveal(&ui); } });
        let toggle = worker.clone();
        tray.on_toggle_vpn(move || toggle.send(Command::Toggle));
        let exit = worker.clone();
        tray.on_exit_requested(move || exit.send(Command::Exit));
    }
    let exit = worker.clone();
    #[cfg(not(target_os = "android"))]
    let hide_to_tray = tray.is_some();
    ui.window().on_close_requested(move || {
        #[cfg(target_os = "android")]
        { slint::CloseRequestResponse::HideWindow }
        #[cfg(not(target_os = "android"))]
        {
            if hide_to_tray { slint::CloseRequestResponse::HideWindow }
            else { exit.send(Command::Exit); slint::CloseRequestResponse::KeepWindowShown }
        }
    });
    #[cfg(target_os = "android")]
    {
        let refresh = worker.clone();
        crate::android::set_service_listener(move |_| refresh.send(Command::RefreshRuntime));
        let weak = ui.as_weak();
        crate::android::set_metrics_listener(move || {
            let weak = weak.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak.upgrade() { apply_android_metrics(&ui); }
            });
        });
        apply_android_metrics(&ui);
    }
    ui.show()?;
    let result = slint::run_event_loop();
    #[cfg(not(target_os = "android"))]
    worker.send(Command::Exit);
    result?;
    Ok(())
}

fn connect_actions(ui: &AppWindow, worker: &WorkerHandle) {
    let toggle = worker.clone();
    ui.on_toggle_vpn(move || toggle.send(Command::Toggle));
    let apply = worker.clone();
    ui.on_apply_uuid(move |text| apply.send(Command::ApplyUuid(text.to_string())));
    let check = worker.clone();
    ui.on_check_updates(move || check.send(Command::CheckUpdates));
    let account = worker.clone();
    ui.on_refresh_account(move || account.send(Command::RefreshAccount));
    let connection = worker.clone();
    ui.on_apply_connection(move |id, fingerprint, domains, applications| {
        let inbound_id = if id.is_empty() { None } else {
            match id.parse::<u64>().ok().filter(|id| *id > 0) {
                Some(id) => Some(id),
                None => { connection.send(Command::ReportError("Некорректный выбор inbound".into())); return; }
            }
        };
        connection.send(Command::ApplyConnection {
            inbound_id, fingerprint: (!fingerprint.is_empty()).then(|| fingerprint.to_string()),
            domains: domains.to_string(), applications: applications.to_string(),
        });
    });
    let select = worker.clone();
    ui.on_select_core(move |index| { if index >= 0 { select.send(Command::SelectCore(index as usize)); } });
    let install = worker.clone();
    ui.on_install_core(move |index| { if index >= 0 { install.send(Command::InstallCore(index as usize)); } });
    let profile = worker.clone();
    ui.on_install_profile(move || profile.send(Command::InstallProfile));
    let application = worker.clone();
    ui.on_download_application(move || application.send(Command::DownloadApplication));
    let export = worker.clone();
    ui.on_export_application(move || export.send(Command::ExportApplication));
    let import = worker.clone();
    ui.on_import_invitation(move || {
        let worker = import.clone();
        #[cfg(target_os = "macos")]
        {
            // AppKit's file panel belongs on its main thread.
            let selected = rfd::FileDialog::new().set_title("Импорт файла подключения MinTun")
                .add_filter("Приглашение MinTun", &["mintun"]).pick_file();
            if let Some(path) = selected { read_invitation_in_thread(worker, path); }
        }
        #[cfg(not(target_os = "macos"))]
        {
            let failure = worker.clone();
            if let Err(error) = std::thread::Builder::new().name("mintun-import".into()).spawn(move || {
                #[cfg(target_os = "android")]
                let selected = crate::android::pick_invitation();
                #[cfg(not(target_os = "android"))]
                let selected = (|| -> Result<Option<String>> {
                    let path = rfd::FileDialog::new().set_title("Импорт файла подключения MinTun")
                        .add_filter("Приглашение MinTun", &["mintun"]).pick_file();
                    path.map(read_invitation).transpose()
                })();
                match selected {
                    Ok(Some(text)) => worker.send(Command::Import(text)),
                    Ok(None) => (),
                    Err(error) => worker.send(Command::ReportError(error.to_string())),
                }
            }) { failure.send(Command::ReportError(error.to_string())); }
        }
    });
}

#[cfg(target_os = "macos")]
fn read_invitation_in_thread(worker: WorkerHandle, path: PathBuf) {
    let failure = worker.clone();
    if let Err(error) = std::thread::Builder::new().name("mintun-import".into()).spawn(move || {
        match read_invitation(path) {
            Ok(text) => worker.send(Command::Import(text)),
            Err(error) => worker.send(Command::ReportError(error.to_string())),
        }
    }) { failure.send(Command::ReportError(error.to_string())); }
}

#[cfg(not(target_os = "android"))]
fn read_invitation(path: PathBuf) -> Result<String> {
    use std::io::Read;
    let file = std::fs::File::open(path).context("Не удалось открыть файл подключения")?;
    let mut bytes = Vec::new();
    file.take(crate::profile::MAXIMUM_ENVELOPE_BYTES as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= crate::profile::MAXIMUM_ENVELOPE_BYTES, "Слишком большой файл подключения");
    String::from_utf8(bytes).context("Файл подключения должен быть в UTF-8")
}

fn update_window(ui: &AppWindow, state: &Snapshot, cache: &mut UiCache) {
    ui.set_running(state.running);
    ui.set_busy(state.busy);
    ui.set_checking_updates(state.checking);
    ui.set_can_connect(state.can_connect);
    ui.set_can_install_core(state.can_install_core);
    ui.set_status_text(state.status.as_str().into());
    ui.set_error_text(state.error.as_str().into());
    ui.set_profile_revision(state.profile_revision.as_str().into());
    ui.set_core_version(state.core_version.as_str().into());
    ui.set_has_profile(state.has_profile);
    ui.set_has_profile_update(!state.profile_update_version.is_empty());
    ui.set_has_application_update(!state.application_update_version.is_empty());
    ui.set_profile_update_version(state.profile_update_version.as_str().into());
    ui.set_application_update_version(state.application_update_version.as_str().into());
    ui.set_downloaded_application_path(state.downloaded_application_path.as_str().into());
    ui.set_progress(state.progress);
    ui.set_account_checking(state.account_checking);
    ui.set_account_time(state.account_time.as_str().into());
    ui.set_account_traffic(state.account_traffic.as_str().into());
    ui.set_account_updated(state.account_updated.as_str().into());
    ui.set_account_notice(state.account_notice.as_str().into());
    if cache.inbounds != state.connection_choices {
        let pending = cache.inbounds.get(ui.get_inbound_index().max(0) as usize).map(|choice| choice.id);
        let labels: Vec<SharedString> = state.connection_choices.iter().map(|choice| choice.label.as_str().into()).collect();
        let choices: Vec<InboundChoice> = state.connection_choices.iter().map(|choice| InboundChoice {
            id: choice.id.map(|id| id.to_string()).unwrap_or_default().into(),
            available: choice.available, fingerprint: choice.supports_fingerprint,
        }).collect();
        ui.set_inbound_labels(std::rc::Rc::new(VecModel::from(labels)).into());
        ui.set_inbound_choices(std::rc::Rc::new(VecModel::from(choices)).into());
        let index = pending.and_then(|id| state.connection_choices.iter().position(|choice| choice.id == id)).unwrap_or(0);
        ui.set_inbound_index(index as i32);
        cache.inbounds.clone_from(&state.connection_choices);
    }
    if cache.preferences.as_ref() != Some(&state.preferences) {
        let index = state.connection_choices.iter().position(|choice| choice.id == state.preferences.selected_inbound_id).unwrap_or(0);
        ui.set_inbound_index(index as i32);
        let fingerprint = state.preferences.fingerprint.as_deref()
            .and_then(|value| FINGERPRINTS.iter().position(|choice| *choice == value)).map(|index| index + 1).unwrap_or(0);
        ui.set_fingerprint_index(fingerprint as i32);
        ui.set_custom_domains(state.preferences.domain_suffixes.join("\n").into());
        ui.set_custom_applications(state.preferences.applications.join("\n").into());
        cache.preferences = Some(state.preferences.clone());
    }
    if cache.uuid.as_ref() != Some(&state.uuid) {
        ui.set_uuid_text(state.uuid.as_str().into());
        cache.uuid = Some(state.uuid.clone());
    }
    if cache.versions != state.core_versions {
        let values: Vec<SharedString> = state.core_versions.iter().map(|text| text.as_str().into()).collect();
        let model: ModelRc<SharedString> = std::rc::Rc::new(VecModel::from(values)).into();
        ui.set_core_versions(model);
        cache.versions.clone_from(&state.core_versions);
    }
    ui.set_selected_core_index(state.selected_core_index);
}

#[cfg(target_os = "windows")]
fn install_windows_repaint_handler(window: &slint::Window) {
    use slint::private_unstable_api::re_exports::{LogicalPoint, LogicalRect, WindowInner};
    use slint::winit_030::{EventResult, WinitWindowAccessor, winit::{
        event::WindowEvent,
        raw_window_handle::{HasWindowHandle, RawWindowHandle},
    }};
    use windows_sys::Win32::{Foundation::RECT, Graphics::Gdi::GetUpdateRect};

    // Backport Slint #13568 for pinned 1.18.1, before winit validates WM_PAINT.
    // Internal paints have no update rect, so ordinary frames stay partial.
    window.on_winit_window_event(|window, event| {
        if matches!(event, WindowEvent::RedrawRequested) {
            window.with_winit_window(|native| {
                let Ok(handle) = native.window_handle() else { return };
                let RawWindowHandle::Win32(handle) = handle.as_raw() else { return };
                let mut rect = RECT { left: 0, top: 0, right: 0, bottom: 0 };
                // The borrowed HWND is live on this window's UI thread.
                if unsafe { GetUpdateRect(handle.hwnd.get() as _, &mut rect, 0) } == 0 { return; }
                let scale = window.scale_factor();
                let dirty = LogicalRect::new(
                    LogicalPoint::new(rect.left as f32 / scale, rect.top as f32 / scale),
                    ((rect.right - rect.left) as f32 / scale, (rect.bottom - rect.top) as f32 / scale).into(),
                );
                WindowInner::from_pub(window).window_adapter().renderer().mark_dirty_region(dirty.into());
            });
        }
        EventResult::Propagate
    });
}

#[cfg(not(target_os = "android"))]
fn reveal(ui: &AppWindow) {
    ui.window().set_minimized(false);
    let _ = ui.show();
}

#[cfg(target_os = "android")]
fn apply_android_metrics(ui: &AppWindow) {
    if let Ok(metrics) = crate::android::ui_metrics() {
        ui.set_inset_top(metrics.inset_top);
        ui.set_inset_bottom(metrics.inset_bottom);
        ui.set_inset_left(metrics.inset_left);
        ui.set_inset_right(metrics.inset_right);
        ui.set_text_scale(metrics.text_scale);
    }
}

fn data_override() -> Result<Option<PathBuf>> {
    #[cfg(target_os = "android")]
    { Ok(None) }
    #[cfg(not(target_os = "android"))]
    {
        let mut args = std::env::args_os().skip(1);
        match args.next() {
            None => Ok(None),
            Some(flag) if flag == "--data-dir" => {
                let path = args.next().context("После --data-dir укажите папку данных")?;
                ensure!(args.next().is_none(), "Допустимые аргументы: --data-dir <папка>");
                Ok(Some(path.into()))
            }
            _ => anyhow::bail!("Допустимые аргументы: --data-dir <папка>"),
        }
    }
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn tray_available() -> bool { true }

#[cfg(target_os = "linux")]
fn tray_available() -> bool {
    (|| -> Result<bool> {
        let connection = zbus::blocking::Connection::session()?;
        let bus = zbus::blocking::fdo::DBusProxy::new(&connection)?;
        Ok(bus.name_has_owner("org.kde.StatusNotifierWatcher".try_into()?)?)
    })().unwrap_or(false)
}
