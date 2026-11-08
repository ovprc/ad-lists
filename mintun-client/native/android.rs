//! Android JNI boundary. The Java foreground VpnService, not the activity, owns libbox.
use std::{path::{Path, PathBuf}, sync::{Arc, Mutex, OnceLock}};

use android_activity::AndroidApp;
use anyhow::{Context, Result, anyhow, bail};
use jni::{JNIEnv, JavaVM, objects::{GlobalRef, JByteArray, JClass, JFloatArray, JObject, JObjectArray, JString, JValue}, sys::{jboolean, jint}};
use zeroize::Zeroize;

use crate::models::{ProxyEndpoint, RuntimeConfiguration};

struct Bridge { vm: JavaVM, class: GlobalRef }
static BRIDGE: OnceLock<Bridge> = OnceLock::new();
type ServiceListener = Arc<dyn Fn(bool) + Send + Sync>;
type MetricsListener = Arc<dyn Fn() + Send + Sync>;
static SERVICE_LISTENER: Mutex<Option<ServiceListener>> = Mutex::new(None);
static METRICS_LISTENER: Mutex<Option<MetricsListener>> = Mutex::new(None);
static EXPORT_CANCEL: Mutex<Option<tokio_util::sync::CancellationToken>> = Mutex::new(None);

pub(crate) fn set_export_cancellation(cancel: Option<tokio_util::sync::CancellationToken>) {
    if let Ok(mut current)=EXPORT_CANCEL.lock() { *current=cancel; }
}
pub(crate) fn cancel_export() -> Result<()> {
    with_env(|env,class| {
        env.call_static_method(class,"cancelExport","()V",&[])?;
        Ok(())
    })
}
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_mintun_client_AppBridge_nativeExportCancelled(_env:JNIEnv<'_>,_class:JClass<'_>)->jboolean {
    EXPORT_CANCEL.lock().ok().and_then(|current|current.as_ref().map(|cancel|cancel.is_cancelled()))
        .unwrap_or(true) as jboolean
}

/// Call before creating the Slint platform/window. Retains an application class, not an Activity.
pub fn initialize(app: AndroidApp) -> Result<()> {
    if BRIDGE.get().is_some() { return initialize_ui(app); }
    // android-activity owns the VM and activity references for this process.
    let vm = unsafe { JavaVM::from_raw(app.vm_as_ptr().cast()) }?;
    let class = {
        let mut env = vm.attach_current_thread()?;
        let activity = unsafe { JObject::from_raw(app.activity_as_ptr().cast()) };
        env.with_local_frame(16, |env| -> Result<GlobalRef> {
            let loader = env.call_method(&activity, "getClassLoader", "()Ljava/lang/ClassLoader;", &[])?.l()?;
            let name = env.new_string("app.mintun.client.AppBridge")?;
            let class = env.call_method(loader, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;", &[JValue::Object(name.as_ref())])?.l()?;
            Ok(env.new_global_ref(class)?)
        })?
    };
    let _ = BRIDGE.set(Bridge { vm, class });
    initialize_ui(app)
}

fn initialize_ui(app: AndroidApp) -> Result<()> {
    #[cfg(feature = "ui")]
    slint::android::init(app).map_err(|error| anyhow!("Could not initialize native Android UI: {error}"))?;
    #[cfg(not(feature = "ui"))]
    let _ = app;
    Ok(())
}

fn with_env<T>(operation: impl FnOnce(&mut JNIEnv<'_>, &JClass<'_>) -> Result<T>) -> Result<T> {
    let bridge = BRIDGE.get().context("Android bridge has not been initialized")?;
    let mut env = bridge.vm.attach_current_thread()?;
    let result = env.with_local_frame(64, |env| -> Result<T> {
        let class = JClass::from(env.new_local_ref(bridge.class.as_obj())?);
        operation(env, &class)
    });
    if env.exception_check()? {
        // Never print a Java/Go exception: parser errors can contain private config fragments.
        env.exception_clear()?;
        bail!("Android operation failed; check VPN permission, invitation format, or embedded core compatibility");
    }
    result
}
fn java_string(env: &mut JNIEnv<'_>, object: JObject<'_>) -> Result<String> {
    Ok(env.get_string(&JString::from(object))?.into())
}

pub fn data_directory() -> Result<PathBuf> {
    with_env(|env, class| {
        let value = env.call_static_method(class, "dataDirectory", "()Ljava/lang/String;", &[])?.l()?;
        Ok(PathBuf::from(java_string(env, value)?))
    })
}
fn transform_state(bytes: &[u8], method: &str) -> Result<Vec<u8>> {
    with_env(|env, class| {
        let input = env.byte_array_from_slice(bytes)?;
        let output = env.call_static_method(class, method, "([B)[B", &[JValue::Object(input.as_ref())])?.l()?;
        let array = JByteArray::from(output);
        let result = env.convert_byte_array(&array)?;
        // Wipe the Java plaintext copy once Rust has copied it into zeroizing storage.
        if method == "unprotectState" {
            let zeros = vec![0_i8; result.len()];
            env.set_byte_array_region(&array, 0, &zeros)?;
        }
        Ok(result)
    })
}
pub fn protect_state(bytes: &[u8]) -> Result<Vec<u8>> { transform_state(bytes, "protectState") }
pub fn unprotect_state(bytes: &[u8]) -> Result<Vec<u8>> { transform_state(bytes, "unprotectState") }

/// Blocking SAF operation; call from the application worker, never the Slint event thread.
pub fn pick_invitation() -> Result<Option<String>> {
    with_env(|env, class| {
        let maximum = i32::try_from(crate::profile::MAXIMUM_ENVELOPE_BYTES)?;
        let value = env.call_static_method(class, "pickInvitation", "(I)Ljava/lang/String;", &[JValue::Int(maximum)])?.l()?;
        if value.is_null() { return Ok(None); }
        Ok(Some(java_string(env, value)?))
    })
}
pub fn core_version() -> Result<String> {
    with_env(|env, class| {
        let value = env.call_static_method(class, "coreVersion", "()Ljava/lang/String;", &[])?.l()?;
        java_string(env, value)
    })
}
pub fn report_startup_error(message: &str) {
    let _ = with_env(|env, class| {
        let text = env.new_string(message)?;
        env.call_static_method(class, "reportStartupError", "(Ljava/lang/String;)V", &[JValue::Object(text.as_ref())])?;
        Ok(())
    });
}
/// Verify APK identity, monotonic versionCode, and the installed signing-certificate lineage.
/// This does not install or execute the download.
pub fn verify_application(path: &Path, expected_version: &str) -> Result<()> {
    let path = path.to_str().context("Android APK path is not UTF-8")?;
    with_env(|env, class| {
        let value = env.new_string(path)?;
        let version = env.new_string(expected_version.strip_prefix('v').unwrap_or(expected_version))?;
        env.call_static_method(class, "verifyApplication", "(Ljava/lang/String;Ljava/lang/String;)V", &[
            JValue::Object(value.as_ref()), JValue::Object(version.as_ref()),
        ])?;
        Ok(())
    })
}

/// Export only through Android's explicit create-document sheet; never install.
pub fn export_application(path: &Path, expected_version: &str) -> Result<()> {
    let path=path.to_str().context("Android APK path is not UTF-8")?;
    with_env(|env,class| {
        let path=env.new_string(path)?;
        let version=env.new_string(expected_version)?;
        env.call_static_method(class,"exportApplication","(Ljava/lang/String;Ljava/lang/String;)V",&[
            JValue::Object(path.as_ref()),JValue::Object(version.as_ref()),
        ])?;
        Ok(())
    })
}

#[derive(Clone, Copy, Debug)]
pub struct UiMetrics {
    pub inset_left: f32, pub inset_top: f32, pub inset_right: f32, pub inset_bottom: f32, pub text_scale: f32,
}
pub fn ui_metrics() -> Result<UiMetrics> {
    with_env(|env, class| {
        let object = env.call_static_method(class, "uiMetrics", "()[F", &[])?.l()?;
        let array = JFloatArray::from(object);
        let mut values = [0_f32; 5];
        env.get_float_array_region(array, 0, &mut values)?;
        Ok(UiMetrics { inset_left: values[0], inset_top: values[1], inset_right: values[2], inset_bottom: values[3], text_scale: values[4] })
    })
}
pub fn set_service_listener(listener: impl Fn(bool) + Send + Sync + 'static) {
    if let Ok(mut slot) = SERVICE_LISTENER.lock() { *slot = Some(Arc::new(listener)); }
}
pub fn set_metrics_listener(listener: impl Fn() + Send + Sync + 'static) {
    if let Ok(mut slot) = METRICS_LISTENER.lock() { *slot = Some(Arc::new(listener)); }
}
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_mintun_client_AppBridge_nativeServiceChanged(_env: JNIEnv<'_>, _class: JClass<'_>, connected: jboolean) {
    let callback = SERVICE_LISTENER.lock().ok().and_then(|slot| slot.clone());
    if let Some(callback) = callback { let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| callback(connected != 0))); }
}
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_mintun_client_AppBridge_nativeMetricsChanged(_env: JNIEnv<'_>, _class: JClass<'_>) {
    let callback = METRICS_LISTENER.lock().ok().and_then(|slot| slot.clone());
    if let Some(callback) = callback { let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| callback())); }
}

pub struct CoreService { proxy: Option<ProxyEndpoint> }
impl CoreService {
    pub fn new() -> Result<Self> {
        let proxy = with_env(|env, class| {
            let value = env.call_static_method(class, "proxy", "()[Ljava/lang/String;", &[])?.l()?;
            if value.is_null() { return Ok(None); }
            let array = JObjectArray::from(value);
            let port = env.get_object_array_element(&array, 0)?;
            let user = env.get_object_array_element(&array, 1)?;
            let password = env.get_object_array_element(&array, 2)?;
            Ok(Some(ProxyEndpoint { port: java_string(env, port)?.parse()?, username: java_string(env, user)?, password: java_string(env, password)? }))
        })?;
        Ok(Self { proxy })
    }
    pub async fn get_version(&self, _directory: &Path) -> Result<String> {
        tokio::task::spawn_blocking(core_version).await?
    }
    pub async fn validate(&self, _directory: &Path, json: &str) -> Result<()> {
        let mut json = json.to_owned();
        tokio::task::spawn_blocking(move || {
            let result = with_env(|env, class| {
                let content = env.new_string(&json)?;
                env.call_static_method(class, "validate", "(Ljava/lang/String;)V", &[JValue::Object(content.as_ref())])?;
                Ok(())
            });
            json.zeroize();
            result
        }).await?
    }
    pub async fn start(&mut self, _directory: &Path, version: &str, mut runtime: RuntimeConfiguration) -> Result<()> {
        anyhow::ensure!(self.get_version(_directory).await?==version,"Выбранная версия не соответствует встроенному ядру Android");
        let proxy = runtime.proxy.clone();
        tokio::task::spawn_blocking(move || {
            let result = with_env(|env, class| {
                let json = env.new_string(&runtime.json)?;
                let user = env.new_string(&runtime.proxy.username)?;
                let password = env.new_string(&runtime.proxy.password)?;
                env.call_static_method(class, "start", "(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;)V", &[
                    JValue::Object(json.as_ref()), JValue::Int(runtime.proxy.port as jint),
                    JValue::Object(user.as_ref()), JValue::Object(password.as_ref()),
                ])?;
                Ok(())
            });
            runtime.json.zeroize();
            result
        }).await??;
        self.proxy = Some(proxy);
        Ok(())
    }
    pub async fn stop(&mut self) -> Result<()> {
        tokio::task::spawn_blocking(|| with_env(|env, class| {
            env.call_static_method(class, "stop", "()V", &[])?;
            Ok(())
        })).await??;
        self.proxy = None;
        Ok(())
    }
    pub fn is_running(&mut self) -> bool {
        let result = with_env(|env, class| Ok(env.call_static_method(class, "isRunning", "()Z", &[])?.z()?));
        let running = result.unwrap_or(false);
        if !running { self.proxy = None; }
        running
    }
    pub fn proxy(&self) -> Option<ProxyEndpoint> { self.proxy.clone() }
}
// No Drop: closing/recreating the native activity must not tear down the foreground VPN.
