use anyhow::{Result, anyhow, bail, ensure};
use std::{path::{Path, PathBuf}, process::Stdio, time::Duration};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, process::{Child, Command}, time::{sleep, timeout}};
use zeroize::{Zeroize, Zeroizing};
use crate::models::{ProxyEndpoint, RuntimeConfiguration};

pub struct CoreService { current: Option<crate::helper::Elevated>, proxy: Option<ProxyEndpoint> }
impl CoreService {
    pub fn new() -> Result<Self> { Ok(Self {current:None,proxy:None}) }
    pub async fn get_version(&self, directory: &Path) -> Result<String> {
        let mut child = CoreProcess::spawn(directory,&["version"],None,true)?;
        let work = async {
            let mut output = child.child.stdout.take().ok_or_else(|| anyhow!("Core output unavailable"))?.take(4097);
            let mut text = Zeroizing::new(Vec::new());
            output.read_to_end(&mut text).await?;
            ensure!(text.len() <= 4096,"Core version output exceeds limit");
            ensure!(child.child.wait().await?.success(),"Core version command failed");
            let text = std::str::from_utf8(&text)?;
            let value = text.lines().find_map(|l| l.strip_prefix("sing-box version ")).and_then(|s| s.split_whitespace().next()).ok_or_else(|| anyhow!("Unrecognized sing-box version output"))?;
            Ok(crate::version::normalize(value)?.to_owned())
        };
        timeout(Duration::from_secs(15),work).await.map_err(|_| anyhow!("Core version query timed out"))?
    }
    pub async fn validate(&self, directory: &Path, json: &str) -> Result<()> {
        let mut child = CoreProcess::spawn(directory,&["check","--disable-color","-c","stdin"],None,false)?;
        timeout(Duration::from_secs(20),async {
            child.configure(json).await?;
            ensure!(child.child.wait().await?.success(),"Core configuration validation failed; configuration output is suppressed to protect credentials");
            Ok(())
        }).await.map_err(|_| anyhow!("Core validation timed out"))?
    }
    pub async fn prepare_core(&self,directory:&Path,version:&str,proxy:Option<&ProxyEndpoint>,cancel:&tokio_util::sync::CancellationToken)->Result<()> {
        crate::helper::Elevated::verify(directory,version,proxy,cancel).await
    }
    pub async fn start(&mut self,directory:&Path,version:&str,mut runtime:RuntimeConfiguration)->Result<()> {
        ensure!(!self.is_running(),"MinTun already owns a running core");
        self.stop().await?;
        validate_proxy(&runtime.proxy)?;
        reject_external_core()?;
        self.current=Some(crate::helper::Elevated::launch(directory,version,&runtime).await?);
        runtime.json.zeroize();
        let ready = timeout(Duration::from_secs(35),async {
            loop {
                ensure!(self.owned_alive(),"Core exited during startup; check core/profile compatibility and TUN permissions");
                if probe_proxy(&runtime.proxy).await && interface_ready(&runtime.interface_name)? { return Ok(()); }
                sleep(Duration::from_millis(150)).await;
            }
        }).await;
        match ready {
            Ok(Ok(())) => { self.proxy=Some(runtime.proxy.clone()); Ok(()) },
            Ok(Err(error)) => { let _ = self.stop().await; Err(error) },
            Err(_) => { let _ = self.stop().await; bail!("Core did not prepare its authenticated SOCKS endpoint and TUN interface within 35 seconds") }
        }
    }
    fn owned_alive(&mut self)->bool {
        self.current.as_ref().is_some_and(crate::helper::Elevated::is_running)
    }
    pub fn is_running(&mut self)->bool { let running=self.proxy.is_some() && self.owned_alive(); if !running { self.proxy=None; } running }
    pub fn proxy(&self)->Option<ProxyEndpoint> {
        let alive=self.current.as_ref().is_some_and(crate::helper::Elevated::is_running);
        if alive { self.proxy.clone() } else { None }
    }
    pub async fn stop(&mut self)->Result<()> {
        self.proxy=None;
        if let Some(mut child)=self.current.take() {child.stop().await?;}
        Ok(())
    }
}
impl Drop for CoreService { fn drop(&mut self) { self.proxy=None; self.current.take(); } }

pub(crate) fn executable(directory:&Path)->Result<PathBuf> {
    let path=directory.join(if cfg!(windows) {"sing-box.exe"} else {"sing-box"});
    let metadata=std::fs::symlink_metadata(&path)?;
    ensure!(metadata.is_file() && !metadata.file_type().is_symlink(),"Core executable must be a regular non-symlink file");
    Ok(std::fs::canonicalize(path)?)
}
pub(crate) struct CoreProcess { pub(crate) child:Child, #[cfg(windows)] _job:WinJob, #[cfg(windows)] console:bool, #[cfg(target_os="macos")] _guardian:Option<crate::helper::MacWatch> }
impl CoreProcess {
    pub(crate) fn spawn(directory:&Path,args:&[&str],working:Option<&Path>,capture:bool)->Result<Self> {
        let exe=executable(directory)?;
        let mut command=Command::new(exe);
        command.args(args).stdin(Stdio::piped()).stdout(if capture {Stdio::piped()} else {Stdio::null()}).stderr(Stdio::null()).kill_on_drop(true);
        if let Some(working)=working { command.current_dir(working); }
        #[cfg(windows)] { command.creation_flags(0x00000004 | if args.first()==Some(&"run") {0x00000010} else {0x08000000}); }
        #[cfg(target_os="linux")] unsafe {
            let parent=libc::getpid();
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG,libc::SIGKILL) != 0 { return Err(std::io::Error::last_os_error()); }
                if libc::getppid()!=parent { return Err(std::io::Error::other("Parent exited")); }
                Ok(())
            });
        }
        let child=command.spawn().map_err(|_|anyhow!("Unable to start selected sing-box executable"))?;
        #[cfg(windows)] let job=WinJob::attach(&child)?;
        #[cfg(target_os="macos")] let guardian=if args.first()==Some(&"run") {Some(crate::helper::MacWatch::attach(child.id().ok_or_else(||anyhow!("Core exited before guardian startup"))?)?)} else {None};
        Ok(Self {child,#[cfg(windows)] _job:job,#[cfg(windows)] console:args.first()==Some(&"run"),#[cfg(target_os="macos")] _guardian:guardian})
    }
    pub(crate) async fn configure(&mut self,json:&str)->Result<()> {
        #[cfg(windows)] if self.console {crate::helper::hide_windows_core(self.child.id().ok_or_else(||anyhow!("Core exited before configuration"))?,&self.child).await?;}
        let mut input=self.child.stdin.take().ok_or_else(||anyhow!("Core input unavailable"))?;
        input.write_all(json.as_bytes()).await.map_err(|_|anyhow!("Core closed its private configuration channel"))?;
        input.shutdown().await?;
        Ok(())
    }
    pub(crate) fn alive(&mut self)->bool { matches!(self.child.try_wait(),Ok(None)) }
    pub(crate) async fn stop(&mut self)->Result<()> {
        if self.alive() {
            #[cfg(unix)] if let Some(pid)=self.child.id() { unsafe { libc::kill(pid as i32,libc::SIGINT); } }
            #[cfg(windows)] if let Some(pid)=self.child.id() { let _=crate::helper::signal_windows_core(pid,&self.child).await; }
            match timeout(Duration::from_secs(6),self.child.wait()).await {
                Ok(result)=>{result?;},
                Err(_)=>{self.child.start_kill()?;timeout(Duration::from_secs(5),self.child.wait()).await.map_err(|_|anyhow!("Owned core did not stop"))??;}
            }
        }
        Ok(())
    }
}
fn validate_proxy(p:&ProxyEndpoint)->Result<()> { ensure!(p.port!=0 && !p.username.is_empty() && !p.password.is_empty() && p.username.len()<=255 && p.password.len()<=255,"Invalid authenticated SOCKS endpoint"); Ok(()) }
async fn probe_proxy(p:&ProxyEndpoint)->bool {
    timeout(Duration::from_millis(700),async {
        let mut stream=tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST,p.port)).await?;
        stream.write_all(&[5,1,2]).await?;
        let mut reply=[0;2]; stream.read_exact(&mut reply).await?;
        if reply!=[5,2] { return Ok::<bool,std::io::Error>(false); }
        let mut auth=Zeroizing::new(Vec::with_capacity(3+p.username.len()+p.password.len()));
        auth.extend_from_slice(&[1,p.username.len() as u8]); auth.extend_from_slice(p.username.as_bytes()); auth.push(p.password.len() as u8); auth.extend_from_slice(p.password.as_bytes());
        stream.write_all(&auth).await?; stream.read_exact(&mut reply).await?;
        Ok(reply==[1,0])
    }).await.is_ok_and(|r|r.unwrap_or(false))
}
fn interface_ready(name:&str)->Result<bool> {
    if name.is_empty() { return Ok(true); }
    #[cfg(unix)] {
        let name=std::ffi::CString::new(name)?;
        Ok(unsafe {libc::if_nametoindex(name.as_ptr())}!=0)
    }
    #[cfg(windows)] { Ok(windows_interface_exists(name)) }
    #[cfg(not(any(unix,windows)))] { Ok(false) }
}
fn reject_external_core()->Result<()> {
    #[cfg(target_os="linux")] for entry in std::fs::read_dir("/proc")? {
        let entry=entry?; if !entry.file_name().to_string_lossy().bytes().all(|b|b.is_ascii_digit()) {continue;}
        if std::fs::read_to_string(entry.path().join("comm")).is_ok_and(|s|s.trim()=="sing-box") { bail!("An external sing-box is running; MinTun will not stop or replace another process"); }
    }
    #[cfg(target_os="macos")] {
        let output=std::process::Command::new("/bin/ps").args(["-axo","comm="]).output()?;
        ensure!(output.status.success(),"Unable to inspect running core ownership");
        ensure!(!String::from_utf8_lossy(&output.stdout).lines().any(|line|Path::new(line.trim()).file_name().is_some_and(|name|name=="sing-box")),"An external sing-box is running; MinTun will not stop another process");
    }
    #[cfg(windows)] { ensure!(!windows_external_core()?,"An external sing-box is running; MinTun will not stop another process"); }
    Ok(())
}

#[cfg(windows)]
struct WinJob(windows_sys::Win32::Foundation::HANDLE);
#[cfg(windows)] unsafe impl Send for WinJob {}
#[cfg(windows)] unsafe impl Sync for WinJob {}
#[cfg(windows)] impl WinJob {
    fn attach(child:&Child)->Result<Self> {
        use windows_sys::Win32::{Foundation::CloseHandle,System::{JobObjects::*,Threading::*}};
        unsafe {
            let job=CreateJobObjectW(std::ptr::null(),std::ptr::null()); ensure!(!job.is_null(),"Unable to create owned core job");
            let guard=Self(job);
            let mut limits:JOBOBJECT_EXTENDED_LIMIT_INFORMATION=std::mem::zeroed(); limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            ensure!(SetInformationJobObject(job,JobObjectExtendedLimitInformation,&limits as *const _ as *const _,std::mem::size_of_val(&limits) as u32)!=0,"Unable to protect core lifetime");
            let handle=OpenProcess(PROCESS_SET_QUOTA|PROCESS_TERMINATE|PROCESS_SUSPEND_RESUME|PROCESS_QUERY_LIMITED_INFORMATION,0,child.id().ok_or_else(||anyhow!("Core already exited"))?);
            ensure!(!handle.is_null(),"Unable to open owned core");
            let assigned=AssignProcessToJobObject(job,handle)!=0;
            let resumed=assigned && NtResumeProcess(handle)>=0;
            CloseHandle(handle);
            ensure!(resumed,"Unable to launch core inside owned process job");
            Ok(guard)
        }
    }
}
#[cfg(windows)] impl Drop for WinJob { fn drop(&mut self) {unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0); }} }
#[cfg(windows)] #[link(name="ntdll")] unsafe extern "system" { fn NtResumeProcess(process:windows_sys::Win32::Foundation::HANDLE)->i32; }
#[cfg(windows)] fn windows_external_core()->Result<bool> {
    use windows_sys::Win32::{Foundation::{CloseHandle,INVALID_HANDLE_VALUE},System::Diagnostics::ToolHelp::*};
    unsafe {
        let snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0); ensure!(snapshot!=INVALID_HANDLE_VALUE,"Unable to inspect running core ownership");
        let mut entry:PROCESSENTRY32W=std::mem::zeroed();entry.dwSize=std::mem::size_of_val(&entry) as u32;
        let mut next=Process32FirstW(snapshot,&mut entry); let mut found=false;
        while next!=0 { let len=entry.szExeFile.iter().position(|c|*c==0).unwrap_or(entry.szExeFile.len()); if String::from_utf16_lossy(&entry.szExeFile[..len]).eq_ignore_ascii_case("sing-box.exe") {found=true;break;} next=Process32NextW(snapshot,&mut entry); }
        CloseHandle(snapshot);Ok(found)
    }
}
#[cfg(windows)] fn windows_interface_exists(name:&str)->bool {
    #[link(name="iphlpapi")] unsafe extern "system" { fn ConvertInterfaceAliasToLuid(alias:*const u16,luid:*mut u64)->u32; }
    let wide:Vec<u16>=name.encode_utf16().chain(Some(0)).collect(); let mut luid=0;
    unsafe {ConvertInterfaceAliasToLuid(wide.as_ptr(),&mut luid)==0}
}
