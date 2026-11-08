use anyhow::{Context, Result, anyhow, bail, ensure};
use serde::{Deserialize,Serialize};
use std::{path::{Path,PathBuf},sync::{Arc,atomic::{AtomicBool,Ordering}},time::Duration};
use tokio::{io::{AsyncRead,AsyncReadExt,AsyncWrite,AsyncWriteExt},time::{timeout,sleep}};
use tokio_util::sync::CancellationToken;
use zeroize::{Zeroize,Zeroizing};
use crate::models::{ProxyEndpoint, RuntimeConfiguration};

const HELPER_FLAG:&str="--mintun-core-helper";
const MAX_REQUEST:usize=16*1024*1024;
const MAX_STARTUP_ERROR: usize = 4096;
#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all="lowercase")]
enum Action { Verify, Run }
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct Request { directory:PathBuf, version:String, action:Action, proxy:Option<ProxyEndpoint>, json:String }
impl Drop for Request {fn drop(&mut self){self.json.zeroize();}}

pub fn needs_elevation()->bool {
    #[cfg(any(target_os="linux",target_os="macos"))] {unsafe {libc::geteuid()!=0}}
    #[cfg(windows)] { !windows_elevated() }
    #[cfg(not(any(windows,target_os="linux",target_os="macos")))] {false}
}

/// Dispatched before GUI initialization; native authorization is used for verify/run only.
pub fn try_run(args:&[String])->Result<bool> {
    #[cfg(windows)] if args.first().is_some_and(|a|a=="--mintun-console-stop" || a=="--mintun-console-hide") { windows_console_stop(args)?;return Ok(true); }
    #[cfg(target_os="macos")] if args.first().is_some_and(|a|a=="--mintun-macos-watch") {macos_watch(args)?;return Ok(true);}
    if !args.first().is_some_and(|a|a==HELPER_FLAG) { return Ok(false); }
    ensure!(!needs_elevation(),"The core helper requires explicit administrator authorization");
    let runtime=tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    #[cfg(target_os="linux")] {
        ensure!(args.len()==1,"Unexpected helper arguments");
        let uid: u32=std::env::var("PKEXEC_UID").map_err(|_|anyhow!("Core helper must be launched using pkexec"))?.parse()?;
        ensure!(uid!=0,"Invalid invoking user");
        runtime.block_on(async {
            use std::os::fd::AsFd;
            // Standard Tokio stdin uses an uncancellable blocking read that stalls runtime Drop.
            let input=tokio::net::unix::pipe::Receiver::from_owned_fd(std::io::stdin().as_fd().try_clone_to_owned()?)?;
            let output=tokio::net::unix::pipe::Sender::from_owned_fd(std::io::stdout().as_fd().try_clone_to_owned()?)?;
            serve(input,output,Some(uid)).await
        })?;
    }
    #[cfg(windows)] {
        ensure!(args.len()==2 && args[1].starts_with(r"\\.\pipe\mintun-core-"),"Invalid helper pipe");
        let name=&args[1];
        runtime.block_on(async {
            let pipe=tokio::net::windows::named_pipe::ClientOptions::new().open(name)?;
            let (read,write)=tokio::io::split(pipe);serve(read,write,None).await
        })?;
    }
    #[cfg(target_os="macos")] {
        use std::os::unix::fs::MetadataExt;
        ensure!(args.len()==2,"Unexpected helper arguments");
        let socket=Path::new(&args[1]);
        let metadata=std::fs::symlink_metadata(socket)?;
        ensure!(!metadata.file_type().is_symlink() && metadata.uid()!=0,"Invalid helper socket owner");
        runtime.block_on(async {
            let stream=tokio::net::UnixStream::connect(socket).await?;
            let (read,write)=stream.into_split();serve(read,write,Some(metadata.uid())).await
        })?;
    }
    #[cfg(not(any(windows,target_os="linux",target_os="macos")))] {bail!("Desktop helper is not supported on this platform");}
    Ok(true)
}

pub struct Elevated { running:Arc<AtomicBool>, stop:CancellationToken, task:Option<tokio::task::JoinHandle<Result<()>>> }
impl Elevated {
    pub async fn launch(directory:&Path,version:&str,runtime:&RuntimeConfiguration)->Result<Self> {
        Self::request(Request {directory:std::fs::canonicalize(directory)?,version:version.into(),action:Action::Run,proxy:None,json:runtime.json.clone()},Some(runtime.working_directory.join("cache.db")),None).await
    }
    pub async fn verify(directory:&Path,version:&str,proxy:Option<&ProxyEndpoint>,cancel:&CancellationToken)->Result<()> {
        let helper=Self::request(Request {directory:std::fs::canonicalize(directory)?,version:version.into(),action:Action::Verify,proxy:proxy.cloned(),json:String::new()},None,Some(cancel)).await?;
        drop(helper);
        Ok(())
    }
    async fn request(value:Request,cache_path:Option<PathBuf>,cancel:Option<&CancellationToken>)->Result<Self> {
        let verifying=value.action==Action::Verify;
        let mut request=Zeroizing::new(serde_json::to_vec(&value)?);
        ensure!(request.len()<=MAX_REQUEST,"Configuration exceeds helper protocol limit");
        let stop=cancel.map(CancellationToken::child_token).unwrap_or_default();
        ensure!(!stop.is_cancelled(),"Операция отменена");
        let running=Arc::new(AtomicBool::new(!verifying));
        #[cfg(target_os="linux")] {
            use std::process::Stdio;
            let mut child=tokio::process::Command::new("pkexec").arg(std::env::current_exe()?).arg(HELPER_FLAG).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).kill_on_drop(true).spawn().map_err(|_|anyhow!("pkexec is required for TUN access; install your distribution's polkit package"))?;
            let mut input=child.stdin.take().ok_or_else(||anyhow!("Helper input unavailable"))?;
            let mut output=child.stdout.take().ok_or_else(||anyhow!("Helper output unavailable"))?;
            tokio::select! {
                _=stop.cancelled()=>bail!("Операция отменена"),
                result=timeout(Duration::from_secs(720),async {
                    input.write_u32(request.len() as u32).await?;input.write_all(&request).await?;input.flush().await?;
                    if let Some(cache)=&cache_path {send_cache(cache,&mut input).await?;}
                    read_startup(&mut output).await
                })=>result.map_err(|_|anyhow!("Administrator authorization/core verification timed out"))??,
            }
            request.zeroize();
            if verifying {timeout(Duration::from_secs(20),child.wait()).await??;return Ok(Self {running,stop,task:None});}
            let cache_path=cache_path.ok_or_else(||anyhow!("Missing runtime cache path"))?;
            let task_stop=stop.clone();let alive=running.clone();
            let task=tokio::spawn(async move {
                let result=monitor(&mut output,&mut input,&task_stop,&cache_path).await;
                alive.store(false,Ordering::Release);
                drop(input);let _=timeout(Duration::from_secs(12),child.wait()).await;
                result
            });
            return Ok(Self {running,stop,task:Some(task)});
        }
        #[cfg(windows)] {
            let name=format!(r"\\.\pipe\mintun-core-{}",uuid::Uuid::new_v4().simple());
            let mut pipe=windows_pipe(&name)?;
            let launched=windows_launch(&name)?;
            tokio::select! {
                _=stop.cancelled()=>bail!("Операция отменена"),
                result=timeout(Duration::from_secs(120),pipe.connect())=>result.map_err(|_|anyhow!("Administrator authorization timed out"))??,
            }
            verify_pipe_client(&pipe,&launched)?;
            tokio::select! {
                _=stop.cancelled()=>bail!("Операция отменена"),
                result=timeout(Duration::from_secs(720),async {
                    pipe.write_u32(request.len() as u32).await?;pipe.write_all(&request).await?;pipe.flush().await?;
                    if let Some(cache)=&cache_path {send_cache(cache,&mut pipe).await?;}
                    read_startup(&mut pipe).await
                })=>result.map_err(|_|anyhow!("Core verification/startup timed out"))??,
            }
            request.zeroize();
            if verifying {return Ok(Self {running,stop,task:None});}
            let cache_path=cache_path.ok_or_else(||anyhow!("Missing runtime cache path"))?;
            let task_stop=stop.clone();let alive=running.clone();
            let task=tokio::spawn(async move {
                let _launched=launched;
                let (mut input,mut output)=tokio::io::split(pipe);
                let result=monitor(&mut input,&mut output,&task_stop,&cache_path).await;
                alive.store(false,Ordering::Release);result
            });
            return Ok(Self {running,stop,task:Some(task)});
        }
        #[cfg(target_os="macos")] {
            use std::os::fd::AsRawFd;
            use std::process::Stdio;
            let socket_dir=tempfile::Builder::new().prefix("mintun-helper-").tempdir()?;
            let socket=socket_dir.path().join("core.sock");
            let listener=tokio::net::UnixListener::bind(&socket)?;
            let quote=|text:&str|format!("'{}'",text.replace('\'',"'\\''"));
            let command=format!("exec {} {} {}",quote(std::env::current_exe()?.to_str().ok_or_else(||anyhow!("Invalid application path"))?),HELPER_FLAG,quote(socket.to_str().ok_or_else(||anyhow!("Invalid helper path"))?));
            let script=format!("do shell script \"{}\" with administrator privileges",command.replace('\\',"\\\\").replace('"',"\\\""));
            let mut child=tokio::process::Command::new("/usr/bin/osascript").args(["-e",&script]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).kill_on_drop(true).spawn()?;
            let (mut stream,_)=tokio::select! {
                _=stop.cancelled()=>bail!("Операция отменена"),
                result=timeout(Duration::from_secs(120),listener.accept())=>result.map_err(|_|anyhow!("Administrator authorization was declined or timed out"))??,
            };
            let mut uid=0;let mut gid=0;
            ensure!(unsafe {libc::getpeereid(stream.as_raw_fd(),&mut uid,&mut gid)}==0 && uid==0,"Unexpected administrator helper peer");
            tokio::select! {
                _=stop.cancelled()=>bail!("Операция отменена"),
                result=timeout(Duration::from_secs(720),async {
                    stream.write_u32(request.len() as u32).await?;stream.write_all(&request).await?;stream.flush().await?;
                    if let Some(cache)=&cache_path {send_cache(cache,&mut stream).await?;}
                    read_startup(&mut stream).await
                })=>result.map_err(|_|anyhow!("Core verification/startup timed out"))??,
            }
            request.zeroize();
            if verifying {timeout(Duration::from_secs(20),child.wait()).await??;return Ok(Self {running,stop,task:None});}
            let cache_path=cache_path.ok_or_else(||anyhow!("Missing runtime cache path"))?;
            let task_stop=stop.clone();let alive=running.clone();
            let task=tokio::spawn(async move {
                let _socket_dir=socket_dir;
                let (mut input,mut output)=stream.into_split();
                let result=monitor(&mut input,&mut output,&task_stop,&cache_path).await;
                alive.store(false,Ordering::Release);
                let _=timeout(Duration::from_secs(12),child.wait()).await;result
            });
            return Ok(Self {running,stop,task:Some(task)});
        }
        #[cfg(not(any(windows,target_os="linux",target_os="macos")))] {bail!("Desktop elevation is not supported");}
    }
    pub fn is_running(&self)->bool {self.running.load(Ordering::Acquire)}
    pub async fn stop(&mut self)->Result<()> {
        self.stop.cancel();
        if let Some(task)=self.task.take() {let result=timeout(Duration::from_secs(80),task).await.map_err(|_|anyhow!("Privileged core shutdown timed out"))??;result?;}
        self.running.store(false,Ordering::Release);Ok(())
    }
}
impl Drop for Elevated {fn drop(&mut self){self.stop.cancel();}}

async fn read_startup<R: AsyncRead + Unpin>(input: &mut R) -> Result<()> {
    match input.read_u8().await.context("Privileged core helper disconnected before its startup response")? {
        1 => Ok(()),
        0 => {
            let size = input.read_u32().await.context("Truncated helper startup diagnostic")? as usize;
            ensure!(size > 0 && size <= MAX_STARTUP_ERROR, "Invalid helper startup diagnostic size");
            let mut bytes = vec![0; size];
            input.read_exact(&mut bytes).await.context("Truncated helper startup diagnostic")?;
            let message = std::str::from_utf8(&bytes).context("Invalid helper startup diagnostic encoding")?;
            bail!("Privileged core startup failed: {message}");
        }
        _ => bail!("Invalid helper startup response"),
    }
}

async fn write_startup_error<W: AsyncWrite + Unpin>(output: &mut W, error: &anyhow::Error) -> Result<()> {
    let mut message = format!("{error:#}");
    if message.is_empty() { message.push_str("Privileged core startup failed"); }
    if message.len() > MAX_STARTUP_ERROR {
        let mut end = MAX_STARTUP_ERROR;
        while !message.is_char_boundary(end) { end -= 1; }
        message.truncate(end);
    }
    output.write_u8(0).await?;
    output.write_u32(message.len() as u32).await?;
    output.write_all(message.as_bytes()).await?;
    output.flush().await?;
    Ok(())
}

async fn serve<R:AsyncRead+Unpin,W:AsyncWrite+Unpin>(mut input:R,mut output:W,uid:Option<u32>)->Result<()> {
    let mut started = false;
    let result = serve_request(&mut input, &mut output, uid, &mut started).await;
    if !started && let Err(error) = &result {
        // Only startup failures use this frame; shutdown bytes remain cache protocol.
        let _ = timeout(Duration::from_secs(3), write_startup_error(&mut output, error)).await;
    }
    result
}

async fn serve_request<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut input: &mut R, mut output: &mut W, uid: Option<u32>, started: &mut bool,
) -> Result<()> {
    let size=timeout(Duration::from_secs(30),input.read_u32()).await?? as usize;
    ensure!(size>0 && size<=MAX_REQUEST,"Invalid helper request size");
    let mut bytes=Zeroizing::new(vec![0;size]);timeout(Duration::from_secs(30),input.read_exact(&mut bytes)).await??;
    let mut request:Request=serde_json::from_slice(&bytes).map_err(|_|anyhow!("Invalid helper request"))?;bytes.zeroize();
    ensure!(crate::version::normalize(&request.version)?==request.version,"Invalid selected core version");
    ensure!(request.action==Action::Verify || request.proxy.is_none(),"Run cannot select a verification route");
    let bundle=crate::core_trust::private_staging()?;
    copy_core(&request.directory,bundle.path(),uid)?;
    if request.action==Action::Run {
        let work=private_runtime(bundle.path())?;
        receive_cache(&mut input,&work.join("cache.db")).await?;
    }
    let cancel=CancellationToken::new();
    let _cancel_on_drop=cancel.clone().drop_guard();
    let trusted=tokio::select! {
        result=crate::core_trust::authenticate(&request.version,request.proxy.as_ref(),&cancel)=>result?,
        _=input.read_u8()=>{cancel.cancel();bail!("Verification cancelled or caller disconnected");}
    };
    crate::core_trust::verify_directory(bundle.path(),&trusted)?;
    if request.action==Action::Verify {
        ensure!(!cancel.is_cancelled(),"Verification cancelled");
        *started = true;
        output.write_u8(1).await?;output.flush().await?;
        return Ok(());
    }
    let work=bundle.path().join("runtime");
    let mut json=crate::config::SensitiveJson(serde_json::from_str(&request.json).map_err(|_|anyhow!("Invalid runtime configuration"))?);
    request.json.zeroize();
    let object=json.0.as_object_mut().ok_or_else(||anyhow!("Invalid runtime configuration"))?;
    object.insert("log".into(),serde_json::json!({"disabled":true}));
    if let Some(cache)=object.get_mut("experimental").and_then(|e|e.get_mut("cache_file")).and_then(serde_json::Value::as_object_mut) {cache.insert("path".into(),serde_json::json!(work.join("cache.db")));}
    let mut configuration=Zeroizing::new(serde_json::to_string(&json.0)?);
    drop(json);
    let mut child=crate::runtime::CoreProcess::spawn(bundle.path(),&["run","--disable-color","-D",work.to_str().ok_or_else(||anyhow!("Invalid helper path"))?,"-c","stdin"],Some(&work),false)?;
    timeout(Duration::from_secs(20),child.configure(&configuration)).await??;configuration.zeroize();
    *started = true;
    output.write_u8(1).await?;output.flush().await?;
    loop {
        tokio::select! {
            _=input.read_u8()=>break,
            _=sleep(Duration::from_millis(150))=>{if !child.alive(){break;}}
        }
    }
    child.stop().await?;
    output.write_u8(0).await?;send_cache(&work.join("cache.db"),&mut output).await?;output.flush().await?;
    drop(bundle);Ok(())
}
fn private_runtime(bundle:&Path)->Result<PathBuf> {
    let path=bundle.join("runtime");
    #[cfg(unix)] let mut builder=std::fs::DirBuilder::new();
    #[cfg(not(unix))] let builder=std::fs::DirBuilder::new();
    #[cfg(unix)] {use std::os::unix::fs::DirBuilderExt;builder.mode(0o700);}
    builder.create(&path)?;
    Ok(path)
}

fn copy_core(source:&Path,destination:&Path,uid:Option<u32>)->Result<()> {
    use std::io::{Read,Write};
    #[cfg(not(unix))] let _=uid;
    let mut total=0u64;
    for (index,entry) in std::fs::read_dir(source)?.enumerate() {
        ensure!(index<256,"Too many core bundle members");
        let entry=entry?;let name=entry.file_name();
        let text=name.to_str().ok_or_else(||anyhow!("Invalid core filename"))?;
        if !crate::updates::executable_file(text) {continue;}
        let mut options=std::fs::OpenOptions::new();options.read(true);
        #[cfg(unix)] {use std::os::unix::fs::OpenOptionsExt;options.custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC|libc::O_NONBLOCK);}
        #[cfg(windows)] {use std::os::windows::fs::OpenOptionsExt;options.custom_flags(0x00200000);}
        let mut input=options.open(entry.path())?;let metadata=input.metadata()?;
        ensure!(metadata.is_file() && metadata.len()>0 && metadata.len()<=256*1024*1024,"Invalid core component size/type");
        #[cfg(windows)] {use std::os::windows::fs::MetadataExt;ensure!(metadata.file_attributes()&0x400==0,"Core component may not be a reparse point");}
        #[cfg(unix)] {
            use std::os::unix::fs::MetadataExt;
            ensure!(uid.is_some_and(|uid|metadata.uid()==uid || metadata.uid()==0) && metadata.mode()&0o022==0,"Unsafe core component owner/permissions");
        }
        total+=metadata.len();ensure!(total<=512*1024*1024,"Core bundle exceeds copy bounds");
        let target=destination.join(&name);
        let mut output=std::fs::OpenOptions::new().create_new(true).write(true).open(&target)?;
        ensure!(std::io::copy(&mut Read::by_ref(&mut input).take(metadata.len()+1),&mut output)?==metadata.len(),"Core component changed during copying");
        output.flush()?;output.sync_all()?;
        #[cfg(unix)] {use std::os::unix::fs::PermissionsExt;std::fs::set_permissions(target,std::fs::Permissions::from_mode(0o700))?;}
    }
    Ok(())
}

#[cfg(windows)] fn windows_elevated()->bool {
    use windows_sys::Win32::{Foundation::CloseHandle,Security::*,System::Threading::*};
    unsafe {let mut token=std::ptr::null_mut();if OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&mut token)==0{return false;}
        let mut elevation:TOKEN_ELEVATION=std::mem::zeroed();let mut size=0;
        let ok=GetTokenInformation(token,TokenElevation,&mut elevation as *mut _ as *mut _,std::mem::size_of_val(&elevation) as u32,&mut size)!=0;
        CloseHandle(token);ok && elevation.TokenIsElevated!=0}
}
#[cfg(windows)] struct WindowsLaunch(windows_sys::Win32::Foundation::HANDLE);
#[cfg(windows)] unsafe impl Send for WindowsLaunch {}
#[cfg(windows)] impl Drop for WindowsLaunch {fn drop(&mut self){unsafe {windows_sys::Win32::Foundation::CloseHandle(self.0);}}}
#[cfg(windows)] fn windows_launch(pipe:&str)->Result<WindowsLaunch> {
    use windows_sys::Win32::UI::Shell::*;
    let exe=std::env::current_exe()?;
    let exe:Vec<u16>=exe.as_os_str().encode_wide().chain(Some(0)).collect();
    let verb:Vec<u16>="runas".encode_utf16().chain(Some(0)).collect();
    let args:Vec<u16>=format!("{HELPER_FLAG} \"{pipe}\"").encode_utf16().chain(Some(0)).collect();
    unsafe {let mut info:SHELLEXECUTEINFOW=std::mem::zeroed();info.cbSize=std::mem::size_of_val(&info) as u32;info.fMask=SEE_MASK_NOCLOSEPROCESS|SEE_MASK_NOASYNC|SEE_MASK_FLAG_NO_UI;info.lpVerb=verb.as_ptr();info.lpFile=exe.as_ptr();info.lpParameters=args.as_ptr();info.nShow=0;
        ensure!(ShellExecuteExW(&mut info)!=0 && !info.hProcess.is_null(),"Administrator authorization was declined or the helper could not start");Ok(WindowsLaunch(info.hProcess))}
}
#[cfg(windows)] use std::os::windows::ffi::OsStrExt;
#[cfg(windows)] fn verify_pipe_client(pipe:&tokio::net::windows::named_pipe::NamedPipeServer,process:&WindowsLaunch)->Result<()> {
    use std::os::windows::io::AsRawHandle;
    #[link(name="kernel32")] unsafe extern "system" {fn GetNamedPipeClientProcessId(pipe:*mut std::ffi::c_void,pid:*mut u32)->i32;}
    unsafe {let mut pid=0;ensure!(GetNamedPipeClientProcessId(pipe.as_raw_handle(),&mut pid)!=0 && windows_sys::Win32::System::Threading::GetProcessId(process.0)==pid,"Unexpected privileged helper pipe client");}Ok(())
}
#[cfg(windows)] pub(crate) async fn signal_windows_core(pid:u32,child:&tokio::process::Child)->Result<()> {windows_console_command(pid,child,"--mintun-console-stop").await}
#[cfg(windows)] pub(crate) async fn hide_windows_core(pid:u32,child:&tokio::process::Child)->Result<()> {windows_console_command(pid,child,"--mintun-console-hide").await}
#[cfg(windows)] async fn windows_console_command(pid:u32,child:&tokio::process::Child,action:&str)->Result<()> {
    use windows_sys::Win32::System::Threading::*;
    use windows_sys::Win32::Foundation::*;
    let creation=unsafe {let h=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,0,pid);ensure!(!h.is_null(),"Core exited");let mut created:FILETIME=std::mem::zeroed();let mut exit=created;let mut kernel=created;let mut user=created;let ok=GetProcessTimes(h,&mut created,&mut exit,&mut kernel,&mut user);CloseHandle(h);ensure!(ok!=0,"Unable to verify core identity");((created.dwHighDateTime as u64)<<32)|created.dwLowDateTime as u64};
    ensure!(child.id()==Some(pid),"Core ownership changed");
    let mut command=tokio::process::Command::new(std::env::current_exe()?);command.args([action,&pid.to_string(),&creation.to_string()]).creation_flags(0x08000000).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).kill_on_drop(true);
    ensure!(timeout(Duration::from_secs(4),command.status()).await??.success(),"Core graceful signal failed");Ok(())
}
#[cfg(windows)] fn windows_console_stop(args:&[String])->Result<()> {
    use windows_sys::Win32::{Foundation::*,System::{Threading::*,Console::*}};
    ensure!(args.len()==3,"Invalid console helper arguments");let pid:u32=args[1].parse()?;let expected:u64=args[2].parse()?;
    unsafe extern "system" fn ignore_console_break(event:u32)->i32 {(event==CTRL_BREAK_EVENT) as i32}
    unsafe {let h=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|0x00100000,0,pid);ensure!(!h.is_null(),"Core exited");
        let mut created:FILETIME=std::mem::zeroed();let mut exit=created;let mut kernel=created;let mut user=created;
        let ok=GetProcessTimes(h,&mut created,&mut exit,&mut kernel,&mut user)!=0 && (((created.dwHighDateTime as u64)<<32)|created.dwLowDateTime as u64)==expected;
        if !ok {CloseHandle(h);bail!("Core identity changed");}
        let mut path=[0u16;32768];let mut len=path.len() as u32;
        let image=QueryFullProcessImageNameW(h,0,path.as_mut_ptr(),&mut len)!=0 && Path::new(&String::from_utf16_lossy(&path[..len as usize])).file_name().is_some_and(|n|n.to_string_lossy().eq_ignore_ascii_case("sing-box.exe"));
        if !image {CloseHandle(h);bail!("Invalid console target");}
        FreeConsole();
        // CREATE_NEW_CONSOLE is initialized by the child after it is resumed.
        // Hide can arrive first: retry only "no console yet", while this exact
        // process is still alive. Other errors must not be hidden or retried.
        let deadline=std::time::Instant::now()+Duration::from_secs(2);
        loop {
            if AttachConsole(pid)!=0 {break;}
            let error=std::io::Error::last_os_error();
            if error.raw_os_error()!=Some(ERROR_INVALID_HANDLE as i32) || WaitForSingleObject(h,0)!=WAIT_TIMEOUT || std::time::Instant::now()>=deadline {
                CloseHandle(h);bail!("Unable to attach core console: {error}");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        if args[0]=="--mintun-console-hide" {windows_sys::Win32::UI::WindowsAndMessaging::ShowWindow(GetConsoleWindow(),0);}
        else {
            // Ctrl+C's ignored flag is inherited (for example from PowerShell).
            // Ctrl+Break still reaches Go's interrupt handler; protect only this
            // signalling helper while broadcasting on the owned core's console.
            if SetConsoleCtrlHandler(Some(ignore_console_break),1)==0 || GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT,0)==0 {
                let error=std::io::Error::last_os_error();FreeConsole();CloseHandle(h);bail!("Unable to signal core console: {error}");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        FreeConsole();CloseHandle(h);
    }Ok(())
}

// macOS lacks Linux PR_SET_PDEATHSIG. A separate pipe guardian survives a helper
// crash and signals only the same process birth identity, never a reused PID.
#[cfg(target_os="macos")]
#[repr(C)]
struct BsdInfo {
    flags:u32,status:u32,xstatus:u32,pid:u32,ppid:u32,uid:u32,gid:u32,ruid:u32,rgid:u32,svuid:u32,svgid:u32,reserved:u32,
    comm:[u8;16],name:[u8;32],nfiles:u32,pgid:u32,jobc:u32,tdev:u32,tpgid:u32,nice:i32,start_seconds:u64,start_microseconds:u64,
}
#[cfg(target_os="macos")]
fn macos_birth(pid:u32)->Option<(u64,u64)> {
    #[link(name="proc")] unsafe extern "C" {fn proc_pidinfo(pid:i32,flavor:i32,arg:u64,buffer:*mut std::ffi::c_void,size:i32)->i32;}
    unsafe {
        let mut info:BsdInfo=std::mem::zeroed();
        let size=std::mem::size_of::<BsdInfo>();
        if proc_pidinfo(pid as i32,3,0,&mut info as *mut _ as *mut _,size as i32)==size as i32 && info.pid==pid {Some((info.start_seconds,info.start_microseconds))} else {None}
    }
}
#[cfg(target_os="macos")]
pub(crate) struct MacWatch { _input:tokio::process::ChildStdin,_watcher:tokio::process::Child }
#[cfg(target_os="macos")]
impl MacWatch {
    pub(crate) fn attach(pid:u32)->Result<Self> {
        let (seconds,micros)=macos_birth(pid).ok_or_else(||anyhow!("Unable to establish owned core identity"))?;
        let mut watcher=tokio::process::Command::new(std::env::current_exe()?).args(["--mintun-macos-watch",&pid.to_string(),&seconds.to_string(),&micros.to_string()]).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn()?;
        let input=watcher.stdin.take().ok_or_else(||anyhow!("Unable to create core guardian pipe"))?;
        Ok(Self {_input:input,_watcher:watcher})
    }
}
#[cfg(target_os="macos")]
fn macos_watch(args:&[String])->Result<()> {
    use std::io::Read;
    ensure!(args.len()==4,"Invalid guardian arguments");
    let pid:u32=args[1].parse()?;let birth=(args[2].parse::<u64>()?,args[3].parse::<u64>()?);
    ensure!(pid>1 && macos_birth(pid)==Some(birth),"Core identity changed before guardian startup");
    let mut byte=[0];let _=std::io::stdin().read(&mut byte);
    if macos_birth(pid)!=Some(birth) {return Ok(());}
    unsafe {libc::kill(pid as i32,libc::SIGINT);}
    for _ in 0..60 {std::thread::sleep(Duration::from_millis(100));if macos_birth(pid)!=Some(birth){return Ok(());}}
    if macos_birth(pid)==Some(birth) {unsafe {libc::kill(pid as i32,libc::SIGKILL);}}
    Ok(())
}

#[cfg(windows)]
fn windows_pipe(name:&str)->Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    use tokio::net::windows::named_pipe::ServerOptions;
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    #[link(name="advapi32")] unsafe extern "system" {
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(text:*const u16,revision:u32,descriptor:*mut *mut std::ffi::c_void,size:*mut u32)->i32;
    }
    #[link(name="kernel32")] unsafe extern "system" {fn LocalFree(memory:*mut std::ffi::c_void)->*mut std::ffi::c_void;}
    // Owner, SYSTEM, and elevated Administrators only. Different-account UAC
    // authorization is supported; the connected process handle is checked too.
    let sddl:Vec<u16>="D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)".encode_utf16().chain(Some(0)).collect();
    unsafe {
        let mut descriptor=std::ptr::null_mut();
        ensure!(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(),1,&mut descriptor,std::ptr::null_mut())!=0,"Unable to secure the privileged helper pipe");
        let mut attributes=SECURITY_ATTRIBUTES {nLength:std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,lpSecurityDescriptor:descriptor,bInheritHandle:0};
        let result=ServerOptions::new().first_pipe_instance(true).reject_remote_clients(true).create_with_security_attributes_raw(name,&mut attributes as *mut _ as *mut std::ffi::c_void);
        LocalFree(descriptor);
        Ok(result?)
    }
}

const MAX_CACHE:u64=64*1024*1024;
async fn send_cache<W:AsyncWrite+Unpin>(path:&Path,output:&mut W)->Result<()> {
    let mut options=std::fs::OpenOptions::new();options.read(true);
    #[cfg(unix)] {use std::os::unix::fs::OpenOptionsExt;options.custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC|libc::O_NONBLOCK);}
    #[cfg(windows)] {use std::os::windows::fs::OpenOptionsExt;options.custom_flags(0x00200000);}
    let file=match options.open(path) {Ok(file)=>file,Err(e) if e.kind()==std::io::ErrorKind::NotFound=>{output.write_u32(0).await?;output.flush().await?;return Ok(())},Err(e)=>return Err(e.into())};
    let metadata=file.metadata()?;ensure!(metadata.is_file() && metadata.len()<=MAX_CACHE,"Cache exceeds transfer bounds or is not a regular file");
    #[cfg(windows)] {use std::os::windows::fs::MetadataExt;ensure!(metadata.file_attributes()&0x400==0,"Cache may not be a reparse point");}
    output.write_u32(metadata.len() as u32).await?;
    let mut input=tokio::fs::File::from_std(file).take(metadata.len());
    ensure!(tokio::io::copy(&mut input,output).await?==metadata.len(),"Cache changed during transfer");
    output.flush().await?;Ok(())
}
async fn receive_cache<R:AsyncRead+Unpin>(input:&mut R,path:&Path)->Result<()> {
    let size=input.read_u32().await? as u64;ensure!(size<=MAX_CACHE,"Cache exceeds transfer bounds");
    if size==0 {return Ok(());}
    let mut bytes=Zeroizing::new(vec![0;size as usize]);input.read_exact(&mut bytes).await?;
    crate::storage::atomic_write(path,&bytes)?;Ok(())
}
async fn monitor<R:AsyncRead+Unpin,W:AsyncWrite+Unpin>(input:&mut R,output:&mut W,stop:&CancellationToken,cache:&Path)->Result<()> {
    let marker=tokio::select! {
        _=stop.cancelled()=>{output.write_u8(0).await?;output.flush().await?;timeout(Duration::from_secs(15),input.read_u8()).await.map_err(|_|anyhow!("Privileged core did not acknowledge shutdown"))??},
        marker=input.read_u8()=>marker.map_err(|_|anyhow!("Privileged core helper exited unexpectedly"))?
    };
    ensure!(marker==0,"Invalid helper shutdown response");
    timeout(Duration::from_secs(45),receive_cache(input,cache)).await.map_err(|_|anyhow!("Core cache synchronization timed out"))??;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn startup_rejection_is_framed_before_caller_eof() {
        let (mut caller, peer) = tokio::io::duplex(8192);
        let (input, output) = tokio::io::split(peer);
        let helper = tokio::spawn(serve(input, output, None));
        caller.write_u32(MAX_REQUEST as u32 + 1).await.unwrap();
        let marker = timeout(Duration::from_secs(1), caller.read_u8()).await.unwrap();
        assert_eq!(marker.unwrap(), 0, "helper must report startup rejection before closing the transport");
        let size = caller.read_u32().await.unwrap() as usize;
        assert!((1..=4096).contains(&size), "startup diagnostic must have bounded framing");
        let mut message = vec![0; size];
        caller.read_exact(&mut message).await.unwrap();
        assert!(std::str::from_utf8(&message).is_ok());
        assert!(helper.await.unwrap().is_err(), "rejected request must not become successful startup");
    }
    #[tokio::test]
    async fn startup_success_leaves_shutdown_and_cache_framing_unconsumed() {
        let mut input = &[1u8, 0, 0, 0, 0, 0][..];
        read_startup(&mut input).await.unwrap();
        assert_eq!(input, &[0, 0, 0, 0, 0]);
    }
    #[tokio::test]
    async fn startup_diagnostic_bounds_are_checked_before_reading_body() {
        for size in [0, MAX_STARTUP_ERROR as u32 + 1] {
            let (mut sender, mut receiver) = tokio::io::duplex(16);
            sender.write_u8(0).await.unwrap();
            sender.write_u32(size).await.unwrap();
            let result = timeout(Duration::from_secs(1), read_startup(&mut receiver)).await;
            assert!(result.unwrap().is_err());
        }
        for frame in [&[2u8][..], &[0, 0, 0, 0, 1, 0xff][..], &[0, 0, 0, 0, 2, b'a'][..]] {
            let mut input = frame;
            assert!(read_startup(&mut input).await.is_err());
        }
    }
    #[tokio::test]
    async fn startup_error_truncation_preserves_utf8_and_frame_size() {
        let (mut sender, mut receiver) = tokio::io::duplex(MAX_STARTUP_ERROR + 8);
        write_startup_error(&mut sender, &anyhow!("a{}", "я".repeat(MAX_STARTUP_ERROR))).await.unwrap();
        assert_eq!(receiver.read_u8().await.unwrap(), 0);
        let size = receiver.read_u32().await.unwrap() as usize;
        assert_eq!(size, MAX_STARTUP_ERROR - 1);
        let mut bytes = vec![0; size];
        receiver.read_exact(&mut bytes).await.unwrap();
        assert!(std::str::from_utf8(&bytes).is_ok());
    }
    #[tokio::test]
    async fn malformed_helper_request_diagnostic_does_not_echo_credentials() {
        let (mut caller, peer) = tokio::io::duplex(8192);
        let (input, output) = tokio::io::split(peer);
        let helper = tokio::spawn(serve(input, output, None));
        let request = br#"{"unexpected":"sensitive-fixture-credential"}"#;
        caller.write_u32(request.len() as u32).await.unwrap();
        caller.write_all(request).await.unwrap();
        let error = read_startup(&mut caller).await.unwrap_err();
        assert!(!error.to_string().contains("sensitive-fixture-credential"));
        assert!(error.downcast_ref::<std::io::Error>().is_none(), "caller must receive a rejection, not transport EOF");
        assert!(helper.await.unwrap().is_err());
    }
    #[tokio::test]
    async fn elevated_cache_roundtrip_preserves_bytes_without_shared_root_paths() {
        let root=tempfile::tempdir().unwrap();let source=root.path().join("source.db");
        let runtime=private_runtime(root.path()).unwrap();let target=runtime.join("cache.db");
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&runtime).unwrap().permissions().mode()&0o777,0o700);
        }
        std::fs::write(&source,b"synthetic cache fixture").unwrap();
        let (mut sender,mut receiver)=tokio::io::duplex(8192);
        let send=tokio::spawn(async move {send_cache(&source,&mut sender).await.unwrap();});
        receive_cache(&mut receiver,&target).await.unwrap();send.await.unwrap();
        assert_eq!(std::fs::read(target).unwrap(),b"synthetic cache fixture");
    }
    #[cfg(unix)]
    #[test]
    fn fifo_cache_is_rejected_without_bytes_or_stalling_current_thread_runtime() {
        use std::os::unix::{ffi::OsStrExt,fs::OpenOptionsExt};
        let root=tempfile::tempdir().unwrap();let fifo=root.path().join("cache.db");
        let name=std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe {libc::mkfifo(name.as_ptr(),0o600)},0);
        let worker_path=fifo.clone();let (finished,completion)=std::sync::mpsc::channel();
        let worker=std::thread::spawn(move || {
            let outcome={
                let runtime=tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
                runtime.block_on(async {
                    let (mut sender,mut receiver)=tokio::io::duplex(16);
                    let result=timeout(Duration::from_millis(500),send_cache(&worker_path,&mut sender)).await;
                    drop(sender);
                    let mut bytes=Vec::new();receiver.read_to_end(&mut bytes).await.unwrap();
                    (result.map_err(|_|"Cache send timed out".to_owned()).and_then(|result|result.map_err(|error|error.to_string())),bytes)
                })
            };
            let _=finished.send(outcome);
        });
        let first=completion.recv_timeout(Duration::from_secs(2));let prompt=first.is_ok();
        let outcome=match first {
            Ok(outcome)=>Some(outcome),
            Err(_)=>{
                // Release the old blocking read-open without blocking this test's cleanup.
                let _release=std::fs::OpenOptions::new().read(true).write(true)
                    .custom_flags(libc::O_NONBLOCK|libc::O_NOFOLLOW|libc::O_CLOEXEC).open(&fifo).ok();
                completion.recv_timeout(Duration::from_secs(2)).ok()
            }
        };
        if outcome.is_some() || worker.is_finished() {worker.join().unwrap();}
        assert!(prompt,"FIFO cache stalled the current-thread runtime before rejection");
        let (result,bytes)=outcome.expect("cache worker did not finish after FIFO cleanup");
        assert!(result.unwrap_err().contains("not a regular file"));
        assert!(bytes.is_empty(),"rejected FIFO cache emitted transfer bytes before consumer EOF");
    }
    #[tokio::test]
    async fn oversized_helper_cache_is_rejected_before_allocating_or_writing() {
        let root=tempfile::tempdir().unwrap();let target=root.path().join("cache.db");
        let (mut sender,mut receiver)=tokio::io::duplex(16);sender.write_u32(MAX_CACHE as u32+1).await.unwrap();
        assert!(receive_cache(&mut receiver,&target).await.is_err());assert!(!target.exists());
    }
}
