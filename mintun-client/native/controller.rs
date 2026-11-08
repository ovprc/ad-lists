use crate::{account::{self, AccountClient, AccountSnapshot}, config, models::*, paths::Paths, preferences::{self, ConnectionPreferences}, profile, storage, updates::{self, UpdateClient}, version};
#[cfg(target_os = "android")]
use crate::android::CoreService;
#[cfg(not(target_os = "android"))]
use crate::runtime::CoreService;
use anyhow::{Context, Result, bail, ensure};
use std::{cmp::Ordering, path::Path, sync::Arc, time::{Duration, SystemTime}};
use tokio::{sync::mpsc, task::JoinHandle};
use tokio_util::sync::CancellationToken;

const CHECK_INTERVAL: Duration = Duration::from_secs(12 * 60 * 60);

pub enum Command {
    Toggle,
    Import(String),
    ApplyUuid(String),
    CheckUpdates,
    RefreshAccount,
    ApplyConnection { inbound_id: Option<u64>, fingerprint: Option<String>, domains: String, applications: String },
    SelectCore(usize),
    InstallCore(usize),
    InstallProfile,
    DownloadApplication,
    ExportApplication,
    ReportError(String),
    RefreshRuntime,
    Exit,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ConnectionChoice {
    pub id: Option<u64>,
    pub label: String,
    pub available: bool,
    pub supports_fingerprint: bool,
}

#[derive(Clone)]
pub struct Snapshot {
    pub running: bool,
    pub busy: bool,
    pub checking: bool,
    pub can_connect: bool,
    pub can_install_core: bool,
    pub status: String,
    pub error: String,
    pub profile_name: String,
    pub profile_revision: String,
    pub core_version: String,
    pub minimum_core_version: String,
    pub uuid: String,
    pub core_versions: Vec<String>,
    pub selected_core_index: i32,
    pub profile_update_version: String,
    pub application_update_version: String,
    pub downloaded_application_path: String,
    pub progress: f32,
    pub has_profile: bool,
    pub account_checking: bool,
    pub account_time: String,
    pub account_traffic: String,
    pub account_updated: String,
    pub account_notice: String,
    pub connection_choices: Vec<ConnectionChoice>,
    pub preferences: ConnectionPreferences,
}

pub enum Event {
    State(Snapshot),
    RevealError,
    Stopped,
}

type Notify = Arc<dyn Fn(Event) + Send + Sync>;

#[derive(Clone)]
pub struct WorkerHandle {
    sender: mpsc::UnboundedSender<Command>,
    lifetime: CancellationToken,
}

impl WorkerHandle {
    pub fn send(&self, command: Command) {
        if matches!(command, Command::Exit) { self.lifetime.cancel(); }
        let _ = self.sender.send(command);
    }
}

pub struct Controller {
    paths: Paths,
    state: ClientState,
    core: CoreService,
    version: String,
    releases: Vec<CoreRelease>,
    selected: Option<usize>,
    pending_profile: Option<ProfileContent>,
    pending_application: Option<ApplicationRelease>,
    downloaded_application: String,
    downloaded_release: Option<ApplicationRelease>,
    status: String,
    error: String,
    busy: bool,
    checking: bool,
    progress: f32,
    last_check: Option<SystemTime>,
    account_client: Option<AccountClient>,
    account_checking: bool,
    account_error: String,
    last_account_check: Option<SystemTime>,
    connection_choices: Vec<ConnectionChoice>,
    notify: Notify,
}

struct CheckResult {
    releases: Option<Vec<CoreRelease>>,
    profile: Option<Option<ProfileContent>>,
    application: Option<Option<ApplicationRelease>>,
    errors: Vec<String>,
}

struct CheckTask {
    cancellation: CancellationToken,
    task: JoinHandle<CheckResult>,
    user_requested: bool,
}

struct AccountTask {
    cancellation: CancellationToken,
    task: JoinHandle<Result<AccountSnapshot>>,
    profile_id: String,
    uuid: String,
}

#[cfg(any(target_os = "android", test))]
#[derive(Default)]
struct ActivityControllerOwner {
    session: Option<ActivityControllerSession>,
}

#[cfg(any(target_os = "android", test))]
struct ActivityControllerSession {
    root: std::path::PathBuf,
    worker: WorkerHandle,
    observer: Arc<std::sync::Mutex<Notify>>,
}

#[cfg(any(target_os = "android", test))]
impl ActivityControllerOwner {
    fn attach(&mut self, paths: Paths, notify: Notify) -> Result<WorkerHandle> {
        if let Some(session) = self.session.as_mut().filter(|session| !session.worker.sender.is_closed()) {
            ensure!(session.root == paths.root, "Нельзя менять папку активного контроллера");
            ensure!(!session.worker.lifetime.is_cancelled(), "MinTun завершает работу; дождитесь закрытия приложения");
            *session.observer.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = notify;
            session.worker.send(Command::RefreshRuntime);
            return Ok(session.worker.clone());
        }
        let root = paths.root.clone();
        let observer = Arc::new(std::sync::Mutex::new(notify));
        let delivery = observer.clone();
        let worker = Controller::spawn_worker(paths, Arc::new(move |event| {
            // Never hold the observer lock while calling UI code.
            let notify = delivery.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
            notify(event);
        }))?;
        self.session = Some(ActivityControllerSession { root, worker: worker.clone(), observer });
        Ok(worker)
    }
}

impl Controller {
    pub fn spawn(paths: Paths, notify: Notify) -> Result<WorkerHandle> {
        #[cfg(target_os = "android")]
        {
            static OWNER: std::sync::Mutex<ActivityControllerOwner> =
                std::sync::Mutex::new(ActivityControllerOwner { session: None });
            OWNER.lock().unwrap_or_else(std::sync::PoisonError::into_inner).attach(paths, notify)
        }
        #[cfg(not(target_os = "android"))]
        { Self::spawn_worker(paths, notify) }
    }

    fn spawn_worker(paths: Paths, notify: Notify) -> Result<WorkerHandle> {
        let state = storage::load(&paths.state_file)?.unwrap_or_default();
        ensure!(state.format == 1 && state.feed.is_some() == state.profile.is_some(),
            "Некорректное состояние приложения. Сохраните папку данных и повторно импортируйте профиль в отдельную папку.");
        if let (Some(feed), Some(content)) = (&state.feed, &state.profile) {
            ensure!(feed.id == content.profile_id, "Сохранённый профиль не соответствует каналу обновлений");
            profile::validate_profile(content)?;
        }
        if !state.core_directory.is_empty() {
            ensure!(paths.owns_core(Path::new(&state.core_directory)) || !Path::new(&state.core_directory).exists(),
                "Выбранное ядро находится вне папки приложения");
        }
        let core = CoreService::new()?;
        let mut controller = Self {
            paths, state, core, version: String::new(), releases: Vec::new(), selected: None,
            pending_profile: None, pending_application: None, downloaded_application: String::new(),
            downloaded_release: None,
            status: "Проверка локального ядра…".into(), error: String::new(), busy: true,
            checking: false, progress: -1.0, last_check: None, notify,
            account_client: None, account_checking: false, account_error: String::new(),
            last_account_check: None, connection_choices: Vec::new(),
        };
        controller.refresh_connection_choices();
        let (sender, receiver) = mpsc::unbounded_channel();
        let lifetime = CancellationToken::new();
        let handle = WorkerHandle { sender, lifetime: lifetime.clone() };
        std::thread::Builder::new().name("mintun-controller".into()).spawn(move || {
            match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                Ok(runtime) => runtime.block_on(controller.run(receiver, lifetime)),
                Err(error) => (controller.notify)(Event::State(Snapshot {
                    running: false, busy: false, checking: false, can_connect: false,
                    can_install_core: false, status: "Не удалось запустить обработчик приложения".into(),
                    error: error.to_string(), profile_name: String::new(), profile_revision: String::new(),
                    core_version: String::new(), minimum_core_version: String::new(), uuid: String::new(),
                    core_versions: Vec::new(), selected_core_index: -1, profile_update_version: String::new(),
                    application_update_version: String::new(), downloaded_application_path: String::new(),
                    progress: -1.0, has_profile: false,
                    account_checking: false, account_time: "Нет данных".into(), account_traffic: "Нет данных".into(),
                    account_updated: String::new(), account_notice: String::new(),
                    connection_choices: Vec::new(), preferences: ConnectionPreferences::default(),
                })),
            }
        })?;
        Ok(handle)
    }

    async fn run(mut self, mut receiver: mpsc::UnboundedReceiver<Command>, lifetime: CancellationToken) {
        self.emit();
        if let Err(error) = self.initialize(&lifetime).await { self.fail(error); }
        self.busy = false;
        self.emit();
        let mut check = self.begin_check(&lifetime, false).ok();
        let mut account_check = if self.core.is_running() { self.begin_account(&lifetime).ok() } else { None };
        let mut clock = tokio::time::interval(Duration::from_secs(60));
        clock.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            let was_running = self.core.is_running();
            tokio::select! {
                command = receiver.recv() => {
                    let Some(command) = command else {
                        if let Some(task) = account_check.take() { cancel_account(task).await; }
                        #[cfg(not(target_os = "android"))]
                        { if let Some(task) = check.take() { cancel_check(task).await; } let _ = self.core.stop().await; }
                        return;
                    };
                    if matches!(command, Command::Exit) {
                        if let Some(task) = account_check.take() { cancel_account(task).await; }
                        if let Some(task) = check.take() { cancel_check(task).await; }
                        self.checking = false;
                        self.busy = true;
                        self.status = "Отключение VPN…".into();
                        self.emit();
                        if let Err(error) = self.core.stop().await { self.fail(error); }
                        self.busy = false;
                        self.emit();
                        (self.notify)(Event::Stopped);
                        return;
                    }
                    if matches!(command, Command::RefreshRuntime) {
                        self.observe_exit(was_running);
                        self.emit();
                        continue;
                    }
                    if matches!(command, Command::RefreshAccount) {
                        if account_check.is_none() {
                            if let Err(error) = self.begin_account(&lifetime).map(|task| account_check = Some(task)) {
                                self.account_error = error.to_string();
                            }
                        }
                        self.emit();
                        continue;
                    }
                    if matches!(command, Command::CheckUpdates) {
                        let mut failed = false;
                        if check.is_none() {
                            match self.begin_check(&lifetime, true) {
                                Ok(task) => check = Some(task),
                                Err(error) => { self.fail(error); failed = true; }
                            }
                        }
                        self.emit();
                        if failed { (self.notify)(Event::RevealError); }
                        continue;
                    }
                    if let Command::SelectCore(index) = command {
                        if index < self.releases.len() { self.selected = Some(index); }
                        self.emit();
                        continue;
                    }
                    if let Some(task) = check.take() { cancel_check(task).await; }
                    self.checking = false;
                    if let Some(task) = account_check.take() { cancel_account(task).await; }
                    self.account_checking = false;
                    self.account_client = None;
                    self.last_account_check = None;
                    self.busy = true;
                    self.error.clear();
                    self.progress = -1.0;
                    self.status = operation_label(&command).into();
                    self.emit();
                    if let Err(error) = self.execute(command, &lifetime).await { self.fail(error); }
                    self.busy = false;
                    self.progress = -1.0;
                    if self.core.is_running() {
                        if let Ok(task) = self.begin_account(&lifetime) { account_check = Some(task); }
                    }
                    self.emit();
                    if !self.error.is_empty() && !lifetime.is_cancelled() { (self.notify)(Event::RevealError); }
                }
                result = async { (&mut check.as_mut().unwrap().task).await }, if check.is_some() => {
                    let user_requested = check.as_ref().is_some_and(|task| task.user_requested);
                    check = None;
                    self.checking = false;
                    match result {
                        Ok(result) => self.apply_check(result),
                        Err(error) if !error.is_cancelled() => self.fail(error.into()),
                        _ => (),
                    }
                    self.emit();
                    if user_requested && !self.error.is_empty() { (self.notify)(Event::RevealError); }
                }
                result = async { (&mut account_check.as_mut().unwrap().task).await }, if account_check.is_some() => {
                    let request = account_check.take().unwrap();
                    self.account_checking = false;
                    if request.uuid == self.state.uuid
                        && self.state.profile.as_ref().is_some_and(|profile| profile.profile_id == request.profile_id) {
                        match result {
                            Ok(Ok(snapshot)) => {
                                if let Err(error) = self.apply_account(request.profile_id.clone(), snapshot) {
                                    self.account_error = error.to_string();
                                }
                            }
                            Ok(Err(error)) => self.account_error = error.to_string(),
                            Err(_) => self.account_error = "Не удалось обновить данные аккаунта".into(),
                        }
                    }
                    self.emit();
                }
                _ = clock.tick() => {
                    let due = self.last_check.and_then(|last| SystemTime::now().duration_since(last).ok())
                        .is_none_or(|elapsed| elapsed >= CHECK_INTERVAL);
                    if due && check.is_none() && !lifetime.is_cancelled() {
                        match self.begin_check(&lifetime, false) {
                            Ok(task) => check = Some(task),
                            Err(error) => self.fail(error),
                        }
                        self.emit();
                    }
                    if was_running && account_check.is_none()
                        && self.last_account_check.and_then(|last| SystemTime::now().duration_since(last).ok())
                            .is_none_or(|elapsed| elapsed >= Duration::from_secs(60))
                        && !lifetime.is_cancelled() {
                        if let Ok(task) = self.begin_account(&lifetime) { account_check = Some(task); }
                        self.emit();
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(2)), if was_running => {
                    if self.observe_exit(was_running) { self.emit(); }
                }
            }
        }
    }

    fn observe_exit(&mut self, was_running: bool) -> bool {
        if was_running && !self.core.is_running() {
            self.error = "VPN отключён: ядро завершилось или системное разрешение отозвано. Проверьте подключение и включите VPN снова.".into();
            self.status = "VPN выключен".into();
            true
        } else { false }
    }

    async fn initialize(&mut self, cancel: &CancellationToken) -> Result<()> {
        ensure!(!cancel.is_cancelled(), "Операция отменена");
        #[cfg(target_os = "android")]
        {
            let directory = self.paths.bundled_core()?;
            self.version = self.core.get_version(&directory).await?;
            let mut candidate = self.state.clone();
            candidate.core_directory = directory.to_string_lossy().into_owned();
            ensure!(!cancel.is_cancelled(), "Операция отменена");
            self.save(candidate)?;
        }
        #[cfg(not(target_os = "android"))]
        {
            if !self.state.core_directory.is_empty() && Path::new(&self.state.core_directory).is_dir() {
                ensure!(self.paths.owns_core(Path::new(&self.state.core_directory)), "Недопустимый каталог ядра");
                self.version = self.core.get_version(Path::new(&self.state.core_directory)).await?;
            } else {
                let name = Path::new(&self.state.core_directory).file_name().and_then(|s| s.to_str()).unwrap_or("");
                ensure!(self.state.core_directory.is_empty() || name.starts_with("bundled-"),
                    "Выбранное ядро недоступно. Восстановите его файлы или явно установите другую версию в разделе обновлений.");
                let source = self.paths.bundled_core()?;
                let version = self.core.get_version(&source).await?;
                ensure!(!version.is_empty() && version.bytes().all(|c| c.is_ascii_alphanumeric() || b".-+".contains(&c)),
                    "Ядро вернуло некорректную версию");
                if !self.state.core_directory.is_empty() {
                    let expected = format!("bundled-{version}");
                    ensure!(name == expected || name.strip_prefix(&(expected + "-")).is_some_and(|tail| uuid::Uuid::parse_str(tail).is_ok()),
                        "Встроенное ядро отличается от ранее выбранного. Выберите замену явно в разделе обновлений.");
                }
                if let Some(profile) = &self.state.profile { ensure_compatible(&version, profile)?; }
                let stage = tempfile::Builder::new().prefix(".seed-").tempdir_in(&self.paths.cores)?;
                for entry in std::fs::read_dir(&source)? {
                    let entry = entry?;
                    let kind = entry.file_type()?;
                    ensure!(!kind.is_symlink(), "Символические ссылки в пакете ядра запрещены");
                    if !kind.is_file() { continue; }
                    let name = entry.file_name();
                    let name = name.to_string_lossy();
                    if updates::executable_file(&name) || name.starts_with("LICENSE") {
                        std::fs::copy(entry.path(), stage.path().join(name.as_ref()))?;
                    }
                }
                ensure!(self.core.get_version(stage.path()).await? == version, "Версия копии ядра изменилась во время подготовки");
                ensure!(!cancel.is_cancelled(), "Операция отменена");
                let destination = self.paths.cores.join(format!("bundled-{version}-{}", uuid::Uuid::new_v4().simple()));
                std::fs::rename(stage.path(), &destination)?;
                let mut candidate = self.state.clone();
                candidate.core_directory = destination.to_string_lossy().into_owned();
                if let Err(error) = self.save(candidate) { let _ = std::fs::remove_dir_all(&destination); return Err(error); }
                self.version = version;
            }
        }
        if let Some(profile) = &self.state.profile { ensure_compatible(&self.version, profile)?; }
        self.status = if self.core.is_running() { "VPN работает" } else if self.state.profile.is_none() {
            "Импортируйте файл подключения и сохраните личный UUID"
        } else { "Готово к подключению" }.into();
        Ok(())
    }

    async fn execute(&mut self, command: Command, cancel: &CancellationToken) -> Result<()> {
        match command {
            Command::ReportError(message) => bail!("{message}"),
            Command::Toggle => {
                if self.core.is_running() {
                    self.core.stop().await?;
                    self.status = "VPN выключен".into();
                } else {
                    self.require_core()?;
                    let profile = self.state.profile.as_ref().context("Сначала импортируйте файл подключения")?;
                    ensure_compatible(&self.version, profile)?;
                    let runtime = config::build(profile, &self.state, &self.paths, false)?;
                    self.core.validate(Path::new(&self.state.core_directory), &runtime.json).await?;
                    ensure!(!cancel.is_cancelled(), "Подключение отменено");
                    self.core.start(Path::new(&self.state.core_directory), &self.version, runtime).await?;
                    self.status = "VPN работает. Обновления идут через защищённый маршрут ядра".into();
                }
            }
            Command::Import(text) => {
                ensure!(!self.core.is_running(), "Выключите VPN перед импортом другого файла подключения");
                let (invitation, content) = profile::read_invitation(&text)?;
                if self.state.feed.as_ref().is_some_and(|feed| feed.id == invitation.feed.id) {
                    if let Some(current) = &self.state.profile { profile::check_revision(current, &content)?; }
                }
                let mut candidate = self.state.clone();
                candidate.feed = Some(invitation.feed.clone());
                candidate.profile = Some(content.clone());
                candidate.account = None;
                candidate.preferences.selected_inbound_id = None;
                self.account_error.clear();
                if !self.version.is_empty() && !version::compatible(&self.version, &content.minimum_core_version)? {
                    ensure!(!cancel.is_cancelled(), "Операция отменена");
                    self.save(candidate)?;
                    self.error = format!("Профиль импортирован. Перед подключением установите sing-box {} или новее", content.minimum_core_version);
                } else {
                    let version = self.version.clone();
                    self.commit(candidate, version, cancel).await?;
                }
                self.pending_profile = None;
                self.status = if self.state.uuid.is_empty() {
                    "Файл подключения проверен и импортирован. Теперь сохраните личный UUID"
                } else {
                    "Файл подключения проверен и импортирован. Ваш UUID сохранён"
                }.into();
            }
            Command::ApplyUuid(text) => {
                let text = text.trim();
                let id = uuid::Uuid::parse_str(text).context("Нужен UUID вида xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")?;
                ensure!(!id.is_nil() && text.len() == 36 && id.hyphenated().to_string().eq_ignore_ascii_case(text),
                    "Нужен непустой UUID вида xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx");
                let mut candidate = self.state.clone();
                candidate.uuid = id.hyphenated().to_string();
                if candidate.uuid != self.state.uuid {
                    candidate.account = None;
                    candidate.preferences.selected_inbound_id = None;
                    self.account_error.clear();
                }
                self.commit(candidate, self.version.clone(), cancel).await?;
                self.status = if self.core.is_running() { "UUID сохранён, VPN перезапущен" } else { "UUID сохранён" }.into();
            }
            Command::ApplyConnection { inbound_id, fingerprint, domains, applications } => {
                ensure!(self.state.profile.is_some(), "Сначала импортируйте файл подключения");
                let preferences = ConnectionPreferences {
                    selected_inbound_id: inbound_id, fingerprint,
                    domain_suffixes: preferences::parse_domain_suffixes(&domains)?,
                    applications: preferences::parse_applications(&applications)?,
                };
                preferences.validate()?;
                if let Some(id) = inbound_id {
                    let cache = self.state.account.as_ref().context("Подключитесь к VPN и обновите список серверов")?;
                    account::validate(&cache.snapshot, &self.state.uuid)?;
                    ensure!(cache.snapshot.inbounds.iter().any(|item| item.id == id && item.available),
                        "Этот inbound недоступен вашему аккаунту");
                }
                if preferences == self.state.preferences {
                    self.status = "Настройки не изменились".into();
                    return Ok(());
                }
                let mut candidate = self.state.clone();
                candidate.preferences = preferences;
                self.commit(candidate, self.version.clone(), cancel).await?;
                self.status = if self.core.is_running() { "Настройки сохранены, VPN переподключён" } else { "Настройки сохранены" }.into();
            }
            Command::InstallProfile => {
                let next = self.pending_profile.clone().context("Нет проверенного обновления конфигурации")?;
                let current = self.state.profile.as_ref().context("Сначала импортируйте файл подключения")?;
                profile::check_revision(current, &next)?;
                self.require_core()?;
                ensure_compatible(&self.version, &next)?;
                let mut candidate = self.state.clone();
                candidate.profile = Some(next);
                self.commit(candidate, self.version.clone(), cancel).await?;
                self.pending_profile = None;
                self.status = "Конфигурация обновлена. Личный UUID сохранён".into();
            }
            Command::InstallCore(index) => self.install_core(index, cancel).await?,
            Command::DownloadApplication => {
                let release = self.pending_application.clone().context("Нет проверенного обновления приложения")?;
                let client = self.update_client()?;
                self.downloaded_application.clear();
                self.downloaded_release = None;
                let notify = self.notify.clone();
                let base = self.snapshot();
                let path = updates::download_application(&client, &release, &self.paths.updates, cancel, move |p| report_progress(&notify, &base, p)).await?;
                self.downloaded_application = path.to_string_lossy().into_owned();
                self.downloaded_release = Some(release);
                self.status = "Обновление скачано и проверено. Оно не запущено и не заменяет работающее приложение".into();
            }
            Command::ExportApplication => {
                #[cfg(target_os = "android")]
                {
                    let release=self.downloaded_release.as_ref().context("Сначала скачайте и проверьте APK")?;
                    let path=std::path::PathBuf::from(&self.downloaded_application);
                    updates::verify_downloaded_application(&path,release,cancel)?;
                    let expected=release.version.clone();
                    crate::android::set_export_cancellation(Some(cancel.clone()));
                    let operation=tokio::task::spawn_blocking(move || crate::android::export_application(&path,&expected));
                    tokio::pin!(operation);
                    let result=tokio::select! {
                        result=&mut operation=>result.context("Не удалось завершить экспорт APK").and_then(|result|result),
                        _=cancel.cancelled()=>{
                            let _=crate::android::cancel_export();
                            let _=operation.await;
                            Err(anyhow::anyhow!("Сохранение APK отменено"))
                        }
                    };
                    crate::android::set_export_cancellation(None);
                    result.context("APK не сохранён. Повторите «Сохранить APK…» и выберите доступную папку; проверенная копия остаётся в MinTun")?;
                    self.status="APK сохранён в выбранную папку. Откройте его вручную; MinTun не запускает установщик".into();
                }
                #[cfg(not(target_os = "android"))]
                bail!("Экспорт APK доступен только на Android");
            }
            _ => (),
        }
        Ok(())
    }

    async fn install_core(&mut self, index: usize, cancel: &CancellationToken) -> Result<()> {
        #[cfg(target_os = "android")]
        { let _ = (index, cancel); bail!("На Android ядро обновляется вместе с приложением"); }
        #[cfg(not(target_os = "android"))]
        {
            let release = self.releases.get(index).cloned().context("Выберите версию из проверенного списка")?;
            ensure!(self.version.is_empty() || version::compare(&release.version, &self.version)? != Ordering::Equal,
                "Эта версия ядра уже установлена");
            if let Some(profile) = &self.state.profile { ensure_compatible(&release.version, profile)?; }
            let client = self.update_client()?;
            let notify = self.notify.clone();
            let base = self.snapshot();
            let staged = updates::download_core(&client, &release, &self.paths.cores, cancel, move |p| report_progress(&notify, &base, p)).await?;
            ensure!(self.paths.owns_core(&staged.directory), "Недопустимый каталог нового ядра");
            let result = async {
                let actual = self.core.get_version(&staged.directory).await?;
                ensure!(version::compare(&actual, &release.version)? == Ordering::Equal, "Версия ядра не соответствует выбранному выпуску");
                ensure!(!cancel.is_cancelled(), "Установка ядра отменена");
                let running=self.core.is_running();
                let proxy=self.core.proxy();
                ensure!(!running || proxy.is_some(),"Прокси ядра не готов. Прямой обход VPN для проверки ядра запрещён");
                self.core.prepare_core(&staged.directory,&actual,proxy.as_ref(),cancel).await?;
                let mut candidate = self.state.clone();
                candidate.core_directory = staged.directory.to_string_lossy().into_owned();
                self.commit(candidate, actual, cancel).await
            }.await;
            if Path::new(&self.state.core_directory) != staged.directory { let _ = std::fs::remove_dir_all(&staged.directory); }
            result?;
            self.selected = Some(index);
            self.status = "Выбранное ядро установлено. Предыдущее ядро сохранено".into();
            Ok(())
        }
    }

    async fn commit(&mut self, candidate: ClientState, version: String, cancel: &CancellationToken) -> Result<()> {
        let was_running = self.core.is_running();
        let runtime = if let Some(profile) = candidate.profile.as_ref().filter(|_| !candidate.core_directory.is_empty()) {
            ensure_compatible(&version, profile)?;
            let runtime = config::build(profile, &candidate, &self.paths, !was_running)?;
            self.core.validate(Path::new(&candidate.core_directory), &runtime.json).await?;
            Some(runtime)
        } else { None };
        ensure!(!cancel.is_cancelled(), "Операция отменена");
        if !was_running {
            self.save(candidate)?;
            self.version = version;
            return Ok(());
        }
        let runtime = runtime.context("Нельзя заменить работающий профиль пустым")?;
        let old = self.state.clone();
        let old_version = self.version.clone();
        self.status = "Применение изменений с перезапуском VPN…".into();
        self.emit();
        let apply = async {
            self.core.stop().await?;
            self.core.start(Path::new(&candidate.core_directory), &version, runtime).await?;
            self.save(candidate)?;
            self.version = version;
            Ok::<_, anyhow::Error>(())
        }.await;
        if let Err(apply_error) = apply {
            let rollback = async {
                self.core.stop().await?;
                let profile = old.profile.as_ref().context("Нет прежней конфигурации для восстановления")?;
                let runtime = config::build(profile, &old, &self.paths, false)?;
                self.core.validate(Path::new(&old.core_directory), &runtime.json).await?;
                self.core.start(Path::new(&old.core_directory), &old_version, runtime).await
            }.await;
            self.state = old;
            self.version = old_version;
            match rollback {
                Ok(()) => bail!("Изменение отменено, прежний VPN восстановлен. {apply_error}"),
                Err(rollback_error) => bail!("Изменение не применено; VPN восстановить не удалось. Старые файлы сохранены. Применение: {apply_error}. Восстановление: {rollback_error}"),
            }
        }
        Ok(())
    }

    fn save(&mut self, state: ClientState) -> Result<()> {
        storage::save(&self.paths.state_file, &state)?;
        self.state = state;
        self.refresh_connection_choices();
        Ok(())
    }

    fn require_core(&self) -> Result<()> {
        ensure!(!self.state.core_directory.is_empty() && !self.version.is_empty(),
            "Ядро не установлено. Распакуйте папку core или установите ядро в разделе обновлений");
        Ok(())
    }

    fn update_client(&mut self) -> Result<UpdateClient> {
        let running = self.core.is_running();
        let proxy = self.core.proxy();
        ensure!(!running || proxy.is_some(), "Прокси ядра не готов. Прямой обход VPN для обновлений запрещён");
        UpdateClient::new(proxy.as_ref())
    }

    fn begin_account(&mut self, lifetime: &CancellationToken) -> Result<AccountTask> {
        ensure!(!lifetime.is_cancelled(), "Завершение работы");
        ensure!(self.core.is_running(), "Данные аккаунта обновляются только через подключённый VPN");
        let profile_id = self.state.profile.as_ref().context("Сначала импортируйте файл подключения")?.profile_id.clone();
        if self.account_client.is_none() {
            let proxy = self.core.proxy().context("Защищённый канал ядра не готов; прямой запрос запрещён")?;
            self.account_client = Some(AccountClient::new(&proxy)?);
        }
        let client = self.account_client.as_ref().unwrap().clone();
        let uuid = self.state.uuid.clone();
        let request_uuid = uuid.clone();
        let cancellation = lifetime.child_token();
        let cancel = cancellation.clone();
        self.account_checking = true;
        self.account_error.clear();
        self.last_account_check = Some(SystemTime::now());
        let task = tokio::spawn(async move { client.fetch(&request_uuid, &cancel).await });
        Ok(AccountTask { cancellation, task, profile_id, uuid })
    }

    fn apply_account(&mut self, profile_id: String, snapshot: AccountSnapshot) -> Result<()> {
        account::validate(&snapshot, &self.state.uuid)?;
        if let Some(cache) = &self.state.account {
            ensure!(snapshot.generated_at >= cache.snapshot.generated_at, "Сервер вернул более старые данные аккаунта");
        }
        let mut candidate = self.state.clone();
        candidate.account = Some(AccountCache { profile_id, snapshot });
        self.save(candidate)?;
        self.account_error.clear();
        Ok(())
    }

    fn refresh_connection_choices(&mut self) {
        let supports_fingerprint = self.state.profile.as_ref().is_some_and(|profile| {
            let Ok(config) = serde_json::from_str(&profile.config_json).map(config::SensitiveJson) else { return false; };
            config.0.get("outbounds").and_then(serde_json::Value::as_array).is_some_and(|outbounds| {
                outbounds.iter().any(|outbound| outbound.get("tag").and_then(serde_json::Value::as_str) == Some(profile.outbound_tag.as_str())
                    && matches!(outbound.get("type").and_then(serde_json::Value::as_str), Some("vless" | "vmess"))
                    && outbound.get("tls").and_then(|tls| tls.get("enabled")).and_then(serde_json::Value::as_bool) == Some(true))
            })
        });
        let mut choices = vec![ConnectionChoice { id: None, label: "Из импортированного профиля".into(),
            available: self.state.profile.is_some(), supports_fingerprint }];
        if let Some(cache) = &self.state.account {
            choices.extend(cache.snapshot.inbounds.iter().map(|item| ConnectionChoice {
                id: Some(item.id),
                label: if item.available { format!("{} · {}", item.label, item.protocol.to_uppercase()) }
                    else { format!("{} · недоступен: {}", item.label, item.unavailable_reason) },
                available: item.available, supports_fingerprint: matches!(item.protocol.as_str(), "vless" | "vmess"),
            }));
        }
        if let Some(id) = self.state.preferences.selected_inbound_id {
            if !choices.iter().any(|item| item.id == Some(id)) {
                choices.push(ConnectionChoice { id: Some(id), label: "Ранее выбранный inbound недоступен".into(),
                    available: false, supports_fingerprint: false });
            }
        }
        self.connection_choices = choices;
    }

    fn begin_check(&mut self, lifetime: &CancellationToken, user_requested: bool) -> Result<CheckTask> {
        ensure!(!lifetime.is_cancelled(), "Завершение работы");
        let client = self.update_client()?;
        let feed = self.state.feed.clone();
        let current = self.state.profile.clone();
        let cancellation = lifetime.child_token();
        let cancel = cancellation.clone();
        self.checking = true;
        let task = tokio::spawn(async move { check_sources(client, feed, current, cancel).await });
        Ok(CheckTask { cancellation, task, user_requested })
    }

    fn apply_check(&mut self, result: CheckResult) {
        if let Some(releases) = result.releases {
            let selected_version = self.selected.and_then(|index| self.releases.get(index)).map(|r| r.version.clone());
            self.releases = releases;
            self.selected = selected_version.and_then(|v| self.releases.iter().position(|r| r.version == v))
                .or_else(|| self.releases.iter().position(|r| self.state.profile.as_ref().is_none_or(|p| version::compatible(&r.version, &p.minimum_core_version).unwrap_or(false))));
        }
        if let Some(profile) = result.profile { self.pending_profile = profile; }
        if let Some(application) = result.application { self.pending_application = application; }
        self.last_check = Some(SystemTime::now());
        self.error = result.errors.join("\n");
        self.status = if self.error.is_empty() { "Проверка обновлений завершена" } else { "Не все источники обновлений доступны. Найденные версии сохранены" }.into();
    }

    fn snapshot(&mut self) -> Snapshot {
        let running = self.core.is_running();
        let minimum = self.state.profile.as_ref().map(|p| p.minimum_core_version.as_str()).unwrap_or("");
        let compatible = self.state.profile.as_ref().is_some_and(|p| version::compatible(&self.version, &p.minimum_core_version).unwrap_or(false));
        let can_connect = self.state.profile.is_some() && uuid::Uuid::parse_str(&self.state.uuid).is_ok_and(|id| !id.is_nil()) && compatible;
        let can_install_core = !cfg!(target_os = "android") && self.selected.and_then(|i| self.releases.get(i)).is_some_and(|r| {
            r.version != self.version && (minimum.is_empty() || version::compatible(&r.version, minimum).unwrap_or(false))
        });
        Snapshot {
            running, busy: self.busy, checking: self.checking, can_connect, can_install_core,
            status: self.status.clone(), error: self.error.clone(),
            profile_name: self.state.feed.as_ref().map(|f| f.name.clone()).unwrap_or_default(),
            profile_revision: self.state.profile.as_ref().map(|p| format!("v{}", p.revision)).unwrap_or_default(),
            core_version: self.version.clone(), minimum_core_version: minimum.into(), uuid: self.state.uuid.clone(),
            core_versions: self.releases.iter().map(|release| {
                let mut label = release.version.clone();
                if release.version == self.version { label.push_str(" · установлено"); }
                if release.version == minimum { label.push_str(" · минимум профиля"); }
                if !minimum.is_empty() && !version::compatible(&release.version, minimum).unwrap_or(false) { label.push_str(" · несовместимо"); }
                label
            }).collect(),
            selected_core_index: self.selected.map(|i| i as i32).unwrap_or(-1),
            profile_update_version: self.pending_profile.as_ref().map(|p| format!("v{}", p.revision)).unwrap_or_default(),
            application_update_version: self.pending_application.as_ref().map(|r| r.version.clone()).unwrap_or_default(),
            downloaded_application_path: self.downloaded_application.clone(), progress: self.progress,
            has_profile: self.state.profile.is_some(),
            account_checking: self.account_checking,
            account_time: account_time(self.state.account.as_ref().map(|cache| &cache.snapshot)),
            account_traffic: account_traffic(self.state.account.as_ref().map(|cache| &cache.snapshot)),
            account_updated: self.state.account.as_ref().map(|cache| {
                let timestamp = chrono::DateTime::from_timestamp(cache.snapshot.generated_at, 0)
                    .map(|time| time.format("%d.%m.%Y %H:%M UTC").to_string()).unwrap_or_default();
                format!("Последнее обновление: {timestamp}{}", if running { "" } else { " · VPN выключен" })
            }).unwrap_or_default(),
            account_notice: if !self.account_error.is_empty() { self.account_error.clone() }
                else if self.account_checking { "Обновление данных через VPN…".into() }
                else if self.state.account.as_ref().is_some_and(|cache| !cache.snapshot.enabled) { "Аккаунт отключён провайдером".into() }
                else if self.state.account.is_none() { "Подключитесь к VPN для получения остатка и списка серверов".into() }
                else { "Сохранённые данные справочные; ограничения применяет сервер".into() },
            connection_choices: self.connection_choices.clone(), preferences: self.state.preferences.clone(),
        }
    }

    fn emit(&mut self) {
        let snapshot = self.snapshot();
        (self.notify)(Event::State(snapshot));
    }

    fn fail(&mut self, error: anyhow::Error) {
        self.error = error.to_string();
        self.status = "Операция не выполнена".into();
    }
}

fn account_time(account: Option<&AccountSnapshot>) -> String {
    let Some(account) = account else { return "Нет данных".into(); };
    if account.activation_pending { return "Начнётся при первом подключении".into(); }
    let Some(expiry) = account.expires_at else { return "Без ограничения".into(); };
    let now = chrono::Utc::now().timestamp();
    let remaining = expiry.saturating_sub(now);
    if remaining <= 0 { return "Срок истёк".into(); }
    let minutes = (remaining + 59) / 60;
    if minutes >= 24 * 60 { format!("{} дн. {} ч.", minutes / (24 * 60), minutes / 60 % 24) }
    else if minutes >= 60 { format!("{} ч. {} мин.", minutes / 60, minutes % 60) }
    else { format!("{minutes} мин.") }
}

fn account_traffic(account: Option<&AccountSnapshot>) -> String {
    let Some(account) = account else { return "Нет данных".into(); };
    let used = account.upload_bytes.saturating_add(account.download_bytes);
    match account.traffic_limit_bytes {
        Some(limit) => format!("{} из {}", traffic_size(limit.saturating_sub(used)), traffic_size(limit)),
        None => format!("Без ограничения · использовано {}", traffic_size(used)),
    }
}

fn traffic_size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 { format!("{:.2} ГиБ", bytes as f64 / (1024.0 * 1024.0 * 1024.0)) }
    else if bytes >= 1024 * 1024 { format!("{:.1} МиБ", bytes as f64 / (1024.0 * 1024.0)) }
    else if bytes >= 1024 { format!("{:.1} КиБ", bytes as f64 / 1024.0) }
    else { format!("{bytes} Б") }
}

async fn cancel_account(task: AccountTask) {
    task.cancellation.cancel();
    let _ = task.task.await;
}

async fn cancel_check(check: CheckTask) {
    check.cancellation.cancel();
    let _ = check.task.await;
}

async fn check_sources(client: UpdateClient, feed: Option<FeedIdentity>, current: Option<ProfileContent>, cancel: CancellationToken) -> CheckResult {
    let mut result = CheckResult { releases: None, profile: None, application: None, errors: Vec::new() };
    #[cfg(not(target_os = "android"))]
    match updates::core_releases(&client, current.as_ref().map(|p| p.minimum_core_version.as_str()), &cancel).await {
        Ok(releases) => result.releases = Some(releases),
        Err(error) if !cancel.is_cancelled() => result.errors.push(format!("Ядро: {error}")),
        _ => (),
    }
    if !cancel.is_cancelled() {
        if let (Some(feed), Some(current)) = (&feed, &current) {
            let fetched = async {
                let bytes = client.get_bytes(&feed.update_url, profile::MAXIMUM_ENVELOPE_BYTES, &cancel).await?;
                let next = profile::decrypt_profile(feed, std::str::from_utf8(&bytes).context("Конфигурация не является UTF-8")?)?;
                profile::check_revision(current, &next)?;
                Ok::<_, anyhow::Error>((next.revision > current.revision).then_some(next))
            }.await;
            match fetched {
                Ok(profile) => result.profile = Some(profile),
                Err(error) if !cancel.is_cancelled() => result.errors.push(format!("Конфигурация: {error}")),
                _ => (),
            }
        }
    }
    if !cancel.is_cancelled() {
        match updates::application_release(&client, env!("CARGO_PKG_VERSION"), &cancel).await {
            Ok(application) => result.application = Some(application),
            Err(error) if !cancel.is_cancelled() => result.errors.push(format!("Приложение: {error}")),
            _ => (),
        }
    }
    result
}

fn ensure_compatible(version: &str, profile: &ProfileContent) -> Result<()> {
    ensure!(version::compatible(version, &profile.minimum_core_version)?,
        "Для этой конфигурации требуется sing-box {} или новее", profile.minimum_core_version);
    Ok(())
}

fn operation_label(command: &Command) -> &'static str {
    match command {
        Command::Toggle => "Изменение состояния VPN…",
        Command::Import(_) => "Проверка подписи файла подключения…",
        Command::ApplyUuid(_) => "Проверка UUID и конфигурации…",
        Command::ApplyConnection { .. } => "Проверка настроек подключения и маршрутизации…",
        Command::InstallCore(_) => "Скачивание и проверка ядра…",
        Command::InstallProfile => "Проверка новой конфигурации…",
        Command::DownloadApplication => "Скачивание приложения без остановки VPN…",
        _ => "Обработка…",
    }
}

fn report_progress(notify: &Notify, base: &Snapshot, progress: TransferProgress) {
    let mut state = base.clone();
    state.status = progress.message.clone();
    state.progress = progress.total.filter(|total| *total > 0)
        .map(|total| (progress.received as f64 / total as f64 * 100.0).clamp(0.0, 100.0) as f32).unwrap_or(-1.0);
    notify(Event::State(state));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::mpsc, time::Instant};

    fn next_ready(receiver: &mpsc::Receiver<Event>, deadline: Instant) -> Snapshot {
        loop {
            if let Event::State(state) = receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())).unwrap() {
                if !state.busy { return state; }
            }
        }
    }

    struct ExitOnDrop(WorkerHandle);
    impl Drop for ExitOnDrop { fn drop(&mut self) { self.0.send(Command::Exit); } }

    #[test]
    #[ignore = "Requires MINTUN_TEST_CORE_DIRECTORY and an available platform state keychain; runs version/check only, never TUN"]
    fn activity_rebind_keeps_pending_picker_and_current_state_on_one_controller() {
        let source = std::env::var_os("MINTUN_TEST_CORE_DIRECTORY").expect("set a real core directory");
        let isolated = tempfile::tempdir().unwrap();
        let paths = Paths::new(Some(isolated.path().join("data"))).unwrap();
        let core = paths.cores.join("selected");
        std::fs::create_dir(&core).unwrap();
        for entry in std::fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_file() { std::fs::copy(entry.path(), core.join(entry.file_name())).unwrap(); }
        }
        let mut state = ClientState::default();
        state.core_directory = core.to_string_lossy().into_owned();
        storage::save(&paths.state_file, &state).unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut owner = ActivityControllerOwner::default();
        let (first, old_events) = mpsc::channel();
        let picker_worker = owner.attach(paths.clone(), Arc::new(move |event| { let _ = first.send(event); })).unwrap();
        let _stop = ExitOnDrop(picker_worker.clone());
        assert!(next_ready(&old_events, deadline).error.is_empty());

        let (second, current_events) = mpsc::channel();
        let current = owner.attach(paths.clone(), Arc::new(move |event| { let _ = second.send(event); })).unwrap();
        let fixture: serde_json::Value = serde_json::from_slice(include_bytes!("../tests/fixtures/protocol-dotnet.json")).unwrap();
        // A picker opened by the destroyed Activity completes after the new observer is bound.
        picker_worker.send(Command::Import(fixture["invitation"].to_string()));
        loop {
            let state = next_ready(&current_events, deadline);
            if state.has_profile {
                assert!(state.error.is_empty(), "{}", state.error);
                assert_eq!(state.profile_revision, "v7");
                break;
            }
        }
        current.send(Command::ApplyUuid("22222222-3333-4444-8555-666666666666".into()));
        loop {
            let state = next_ready(&current_events, deadline);
            assert!(state.error.is_empty(), "{}", state.error);
            if state.uuid == "22222222-3333-4444-8555-666666666666" { break; }
        }
        let saved = storage::load(&paths.state_file).unwrap().unwrap();
        assert_eq!(saved.profile.as_ref().unwrap().revision, 7);
        assert_eq!(saved.uuid, "22222222-3333-4444-8555-666666666666");
        current.send(Command::Exit);
        while !matches!(current_events.recv_timeout(deadline.saturating_duration_since(Instant::now())).unwrap(), Event::Stopped) {}
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
            .block_on(async { tokio::time::timeout(Duration::from_secs(5), current.sender.closed()).await }).unwrap();

        // Explicit Exit retires the cancelled session; a later launch loads its committed state.
        let (third, relaunched_events) = mpsc::channel();
        let relaunched = owner.attach(paths, Arc::new(move |event| { let _ = third.send(event); })).unwrap();
        let _stop_relaunched = ExitOnDrop(relaunched.clone());
        let state = next_ready(&relaunched_events, deadline);
        assert!(state.error.is_empty(), "{}", state.error);
        assert!(state.has_profile);
        assert_eq!(state.uuid, "22222222-3333-4444-8555-666666666666");
        relaunched.send(Command::Exit);
        while !matches!(relaunched_events.recv_timeout(deadline.saturating_duration_since(Instant::now())).unwrap(), Event::Stopped) {}
    }
}
