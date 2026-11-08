use anyhow::{Result,anyhow,bail,ensure};
use reqwest::{Client,Response,Url};
use serde::Deserialize;
use sha2::{Digest,Sha256};
use std::{cmp::Ordering,collections::HashSet,fs::{File,OpenOptions},io::{Read,Write},path::{Path,PathBuf},time::Duration};
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;
use crate::{models::{ApplicationRelease,CoreRelease,ProxyEndpoint,StagedCore,TransferProgress},version};
pub(crate) fn executable_file(name: &str) -> bool {
    if name.is_empty() || name.len() > 120 || !name.as_bytes()[0].is_ascii_alphanumeric()
        || name.ends_with('.') || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)) { return false; }
    let stem = name.split('.').next().unwrap_or("");
    if ["con", "prn", "aux", "nul"].iter().any(|reserved| stem.eq_ignore_ascii_case(reserved))
        || (stem.len() == 4 && (stem[..3].eq_ignore_ascii_case("com") || stem[..3].eq_ignore_ascii_case("lpt")) && matches!(stem.as_bytes()[3], b'1'..=b'9')) { return false; }
    name.eq_ignore_ascii_case("sing-box")
        || [".exe", ".dll", ".so", ".dylib"].iter().any(|ext| name.get(name.len().saturating_sub(ext.len())..).is_some_and(|suffix| suffix.eq_ignore_ascii_case(ext)))
        || name.as_bytes().windows(4).enumerate().any(|(index, part)| part.eq_ignore_ascii_case(b".so.") && name[index + 4..].split('.').all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())))
}

const MAX_PACKAGE:u64=256*1024*1024;
const MAX_EXTRACTED:u64=512*1024*1024;
const CORE_FEED:&str="https://api.github.com/repos/SagerNet/sing-box/releases";
const APP_REPOSITORY:&str="ovprc/ad-lists";
const RELEASE_HOSTS:[&str;4]=["github.com","release-assets.githubusercontent.com","objects.githubusercontent.com","github-releases.githubusercontent.com"];

#[derive(Clone)]
pub struct UpdateClient {client:Client}
impl UpdateClient {
    pub fn new(proxy:Option<&ProxyEndpoint>)->Result<Self> {
        let mut builder=Client::builder().no_proxy().https_only(true).redirect(reqwest::redirect::Policy::none()).connect_timeout(Duration::from_secs(20)).timeout(Duration::from_secs(600)).pool_max_idle_per_host(2).pool_idle_timeout(Duration::from_secs(300)).user_agent(concat!("MinTun/",env!("CARGO_PKG_VERSION"))).no_gzip().no_brotli().no_deflate().no_zstd();
        if let Some(proxy)=proxy {
            ensure!(proxy.port!=0 && !proxy.username.is_empty() && !proxy.password.is_empty() && proxy.username.len()<=255 && proxy.password.len()<=255,"Invalid authenticated update proxy");
            // socks5h is essential: destination DNS must travel through the connected VPN.
            builder=builder.proxy(reqwest::Proxy::all(format!("socks5h://127.0.0.1:{}",proxy.port))?.basic_auth(&proxy.username,&proxy.password));
        }
        Ok(Self {client:builder.build()?})
    }
    async fn response(&self,url:&str,restricted:bool,cancel:&CancellationToken)->Result<Response> {
        let mut current=require_https(url)?;
        let original=current.clone();
        for redirects in 0..=6 {
            cancelled(cancel)?;
            if restricted {
                ensure!(current.port_or_known_default()==Some(443) && RELEASE_HOSTS.contains(&current.host_str().unwrap_or("")),"Release download redirected outside GitHub Releases");
                if current.host_str()==Some("github.com") {ensure!(current.path()==original.path() && current.query().is_none(),"Release server changed selected asset");}
            }
            let response=tokio::select! {_=cancel.cancelled()=>bail!("Operation cancelled"),response=self.client.get(current.clone()).header("Accept","application/vnd.github+json").send()=>response.map_err(|_|anyhow!("Сервер обновлений недоступен. Проверьте сеть и повторите проверку. Другой маршрут не использовался."))?};
            if matches!(response.status().as_u16(),301|302|303|307|308) {
                ensure!(redirects<6,"Too many update redirects");
                let location=response.headers().get(reqwest::header::LOCATION).and_then(|s|s.to_str().ok()).ok_or_else(||anyhow!("Invalid update redirect"))?;
                current=require_https(current.join(location).map_err(|_|anyhow!("Invalid update redirect URL"))?.as_str())?;
            } else {
                ensure!(response.status().is_success(),"Update server returned HTTP {}",response.status().as_u16());return Ok(response);
            }
        }
        bail!("Too many update redirects")
    }
    pub async fn get_bytes(&self,url:&str,max:usize,cancel:&CancellationToken)->Result<Vec<u8>> {
        ensure!(max>0,"Invalid update response limit");
        tokio::time::timeout(Duration::from_secs(90),async {
            let mut response=self.response(url,false,cancel).await?;
            ensure!(response.content_length().is_none_or(|n|n<=max as u64),"Update response exceeds size limit");
            let mut bytes=Vec::new();
            loop {
                let chunk=tokio::select! {_=cancel.cancelled()=>bail!("Operation cancelled"),chunk=response.chunk()=>chunk.map_err(|_|anyhow!("Update response stream failed"))?};
                let Some(chunk)=chunk else {break};
                ensure!(chunk.len()<=max.saturating_sub(bytes.len()),"Update response exceeds size limit");bytes.extend_from_slice(&chunk);
            }
            Ok(bytes)
        }).await.map_err(|_|anyhow!("Update metadata request exceeded 90 seconds"))?
    }
}
fn require_https(text:&str)->Result<Url> {
    let url=Url::parse(text).map_err(|_|anyhow!("Invalid update URL"))?;
    ensure!(url.scheme()=="https" && url.host_str().is_some() && url.username().is_empty() && url.password().is_none() && url.fragment().is_none(),"Updates require HTTPS without URL credentials or fragments");Ok(url)
}
fn cancelled(cancel:&CancellationToken)->Result<()> {ensure!(!cancel.is_cancelled(),"Operation cancelled");Ok(())}

#[derive(Deserialize)] struct GithubRelease {tag_name:String,#[serde(default)]draft:bool,#[serde(default)]prerelease:bool,published_at:Option<String>,assets:Vec<Asset>}
#[derive(Deserialize)] struct Asset {name:String,browser_download_url:String,digest:Option<String>,size:u64}
fn digest(asset:&Asset)->Result<String> {
    let value=asset.digest.as_deref().and_then(|s|s.get(..7).filter(|p|p.eq_ignore_ascii_case("sha256:")).map(|_|&s[7..])).ok_or_else(||anyhow!("Release asset lacks a published SHA256 digest"))?;
    ensure!(value.len()==64 && value.bytes().all(|b|b.is_ascii_hexdigit()),"Invalid release SHA256");Ok(value.to_ascii_lowercase())
}
fn platform()->Result<(&'static str,&'static str,&'static str)> {
    let os=if cfg!(target_os="windows"){"windows"}else if cfg!(target_os="linux"){"linux"}else if cfg!(target_os="macos"){"darwin"}else{bail!("This platform uses an embedded core; update the application instead")};
    let arch=if cfg!(target_arch="x86_64"){"amd64"}else if cfg!(target_arch="aarch64"){"arm64"}else{bail!("Unsupported core architecture")};
    Ok((os,arch,if os=="windows"{"zip"}else{"tar.gz"}))
}
fn core_asset(version:&str)->Result<String> {let (os,arch,ext)=platform()?;Ok(format!("sing-box-{version}-{os}-{arch}.{ext}"))}
fn validate_asset(version:&str,url:&str,sha:&str,size:u64,repository:&str,tag:&str,name:&str)->Result<()> {
    ensure!(version::normalize(version)?==version && sha.len()==64 && sha.bytes().all(|b|b.is_ascii_hexdigit()) && size>0 && size<=MAX_PACKAGE,"Invalid release metadata");
    let url=require_https(url)?;
    ensure!(url.host_str()==Some("github.com") && url.port_or_known_default()==Some(443) && url.path()==format!("/{repository}/releases/download/{tag}/{name}") && url.query().is_none(),"Only the official exact-version platform release asset is allowed");Ok(())
}
fn validate_core(release:&CoreRelease)->Result<()> {validate_asset(&release.version,&release.download_url,&release.sha256,release.size,"SagerNet/sing-box",&format!("v{}",release.version),&core_asset(&release.version)?)}
fn add_core(release:GithubRelease,minimum:Option<&str>,seen:&mut HashSet<String>,out:&mut Vec<CoreRelease>)->Result<()> {
    if release.draft {return Ok(());}
    let Ok(normalized)=version::normalize(&release.tag_name) else{return Ok(())};
    if let Some(minimum)=minimum {if !version::compatible(normalized,minimum)? {return Ok(());}}
    let name=core_asset(normalized)?;let mut selected=None;
    for (index,asset) in release.assets.into_iter().filter(|a|a.name==name).enumerate() {
        ensure!(index==0,"Duplicate core release assets");
        let sha=match digest(&asset){Ok(d)=>d,Err(_)=>continue};
        let candidate=CoreRelease {version:normalized.to_owned(),download_url:asset.browser_download_url,sha256:sha,size:asset.size,prerelease:release.prerelease||version::is_prerelease(normalized)?};
        validate_core(&candidate)?;selected=Some(candidate);
    }
    if let Some(selected)=selected {ensure!(seen.insert(selected.version.clone()),"Duplicate core release versions");out.push(selected);}
    Ok(())
}
pub async fn core_releases(client:&UpdateClient,minimum:Option<&str>,cancel:&CancellationToken)->Result<Vec<CoreRelease>> {
    platform()?;if let Some(minimum)=minimum {version::normalize(minimum)?;}
    let bytes=client.get_bytes(&format!("{CORE_FEED}?per_page=30"),16*1024*1024,cancel).await?;
    let releases:Vec<GithubRelease>=serde_json::from_slice(&bytes).map_err(|_|anyhow!("Invalid core release metadata"))?;
    let mut out=Vec::new();let mut seen=HashSet::new();
    for release in releases {cancelled(cancel)?;add_core(release,minimum,&mut seen,&mut out)?;}
    if let Some(minimum)=minimum {let minimum=version::normalize(minimum)?;
        if !out.iter().any(|r|version::compare(&r.version,minimum).is_ok_and(|o|o==Ordering::Equal)) {
            // Missing/deleted old minimum is not fatal; all other transport failures remain visible.
            let url=format!("{CORE_FEED}/tags/v{minimum}");
            match client.get_bytes(&url,4*1024*1024,cancel).await {
                Ok(bytes)=>add_core(serde_json::from_slice(&bytes).map_err(|_|anyhow!("Invalid minimum core release metadata"))?,Some(minimum),&mut seen,&mut out)?,
                Err(e) if e.to_string()=="Update server returned HTTP 404"=>{},Err(e)=>return Err(e)
            }
        }
    }
    out.sort_by(|a,b|version::compare(&b.version,&a.version).unwrap_or(Ordering::Equal));Ok(out)
}

// Privileged authentication must resolve its own exact official release, never
// metadata supplied by the GUI or an arbitrary latest-release response.
pub(crate) async fn official_core_release(client:&UpdateClient,selected:&str,cancel:&CancellationToken)->Result<CoreRelease> {
    ensure!(version::normalize(selected)?==selected,"Core version must be normalized");
    let bytes=client.get_bytes(&format!("{CORE_FEED}/tags/v{selected}"),4*1024*1024,cancel).await?;
    exact_core_release(serde_json::from_slice(&bytes).map_err(|_|anyhow!("Invalid official core release metadata"))?,selected)
}
fn exact_core_release(release:GithubRelease,selected:&str)->Result<CoreRelease> {
    ensure!(!release.draft && version::normalize(&release.tag_name)?==selected,"Official core release tag differs from selected version");
    let name=core_asset(selected)?;
    let mut assets=release.assets.into_iter().filter(|a|a.name==name);
    let asset=assets.next().ok_or_else(||anyhow!("Official core release lacks the selected platform asset"))?;
    ensure!(assets.next().is_none(),"Duplicate official platform assets");
    let sha=digest(&asset)?;
    let candidate=CoreRelease {version:selected.into(),download_url:asset.browser_download_url,sha256:sha,size:asset.size,prerelease:release.prerelease||version::is_prerelease(selected)?};
    validate_core(&candidate)?;Ok(candidate)
}

// The caller owns a private disposable staging directory. This path deliberately
// stops after byte verification and safe extraction: no downloaded process runs.
pub(crate) async fn extract_official_core(client:&UpdateClient,release:&CoreRelease,staging:&Path,cancel:&CancellationToken)->Result<PathBuf> {
    validate_core(release)?;reject_links(staging)?;
    let package=staging.join("package");let bundle=staging.join("bundle");
    std::fs::create_dir(&bundle)?;
    tokio::time::timeout(Duration::from_secs(600),async {
        download(client,&release.download_url,release.size,&release.sha256,&package,cancel,&|_|{},"Authenticating official core").await?;
        let extraction_cancel=cancel.child_token();let _guard=extraction_cancel.clone().drop_guard();
        let version=release.version.clone();let target=bundle.clone();
        tokio::task::spawn_blocking(move ||extract_core(&package,&target,&version,&extraction_cancel)).await??;
        cancelled(cancel)?;Ok(bundle)
    }).await.map_err(|_|anyhow!("Official core authentication exceeded ten minutes"))?
}

async fn download(client:&UpdateClient,url:&str,size:u64,sha:&str,path:&Path,cancel:&CancellationToken,progress:&(impl Fn(TransferProgress)+Send+Sync),message:&str)->Result<()> {
    let mut response=client.response(url,true,cancel).await?;
    ensure!(response.content_length().is_none_or(|n|n==size),"Release size differs from published metadata");
    let file=private_file(path)?;let mut file=tokio::fs::File::from_std(file);let mut hash=Sha256::new();let mut received=0;
    loop {
        let chunk=tokio::select! {_=cancel.cancelled()=>bail!("Operation cancelled"),chunk=response.chunk()=>chunk.map_err(|_|anyhow!("Release download stream failed"))?};
        let Some(chunk)=chunk else{break};
        received+=chunk.len() as u64;ensure!(received<=size,"Release exceeds published size");hash.update(&chunk);
        tokio::select! {_=cancel.cancelled()=>bail!("Operation cancelled"),result=file.write_all(&chunk)=>result?};
        progress(TransferProgress {received,total:Some(size),message:message.into()});
    }
    ensure!(received==size && hex::encode(hash.finalize()).eq_ignore_ascii_case(sha),"Release size or SHA256 verification failed");
    file.flush().await?;file.sync_all().await?;Ok(())
}
fn private_file(path:&Path)->Result<File> {
    let mut options=OpenOptions::new();options.write(true).create_new(true);
    #[cfg(unix)] {use std::os::unix::fs::OpenOptionsExt;options.mode(0o600).custom_flags(libc::O_NOFOLLOW);}
    Ok(options.open(path)?)
}
fn private_directory(path:&Path)->Result<()> {
    reject_links(path)?;std::fs::create_dir_all(path)?;reject_links(path)?;
    #[cfg(unix)] {use std::os::unix::fs::PermissionsExt;std::fs::set_permissions(path,std::fs::Permissions::from_mode(0o700))?;}
    Ok(())
}
fn reject_links(path:&Path)->Result<()> {
    for ancestor in path.ancestors() {match std::fs::symlink_metadata(ancestor) {
        Ok(m)=>{ensure!(!m.file_type().is_symlink(),"Update paths may not traverse symbolic links");#[cfg(windows)] {use std::os::windows::fs::MetadataExt;ensure!(m.file_attributes()&0x400==0,"Update paths may not traverse reparse points");}},
        Err(e) if e.kind()==std::io::ErrorKind::NotFound=>{},Err(e)=>return Err(e.into())
    }}Ok(())
}
pub async fn download_core(client:&UpdateClient,release:&CoreRelease,cores:&Path,cancel:&CancellationToken,progress:impl Fn(TransferProgress)+Send+Sync)->Result<StagedCore> {
    validate_core(release)?;private_directory(cores)?;
    let staging=tempfile::Builder::new().prefix(".staging-").tempdir_in(cores)?;
    let package=staging.path().join("package");let bundle=staging.path().join("bundle");std::fs::create_dir(&bundle)?;
    tokio::time::timeout(Duration::from_secs(600),async {
        download(client,&release.download_url,release.size,&release.sha256,&package,cancel,&progress,"Downloading core").await?;
        let extraction_package=package.clone();let extraction_bundle=bundle.clone();let version=release.version.clone();
        let extraction_cancel=cancel.child_token();let _cancel_on_drop=extraction_cancel.clone().drop_guard();
        tokio::task::spawn_blocking(move ||extract_core(&extraction_package,&extraction_bundle,&version,&extraction_cancel)).await??;
        cancelled(cancel)?;
        #[cfg(not(target_os="android"))] {
            let actual=crate::runtime::CoreService::new()?.get_version(&bundle).await?;
            ensure!(actual==release.version,"Extracted core version differs from selected release");
        }
        #[cfg(target_os="android")] {bail!("Android core updates are delivered only with application updates");}
        let destination=cores.join(format!("{}-{}-{}",release.version,&release.sha256[..12],uuid::Uuid::new_v4().simple()));
        cancelled(cancel)?;reject_links(cores)?;std::fs::rename(&bundle,&destination)?;
        progress(TransferProgress {received:release.size,total:Some(release.size),message:"Core verified and staged".into()});
        Ok(StagedCore {directory:destination,version:release.version.clone()})
    }).await.map_err(|_|anyhow!("Core download exceeded ten minutes; active core was not changed"))?
}

fn archive_name(path:&str,prefix:&str,directory:bool)->Result<Option<String>> {
    ensure!(path.len()<=240 && !path.contains(['\\',':']) && !path.starts_with('/'),"Unsafe archive path");
    let path=path.strip_suffix('/').unwrap_or(path);let parts:Vec<_>=path.split('/').collect();
    ensure!(!parts.is_empty() && parts.len()<=2 && parts.iter().all(|p|!p.is_empty() && *p!="." && *p!=".." && !p.ends_with(['.',' '])),"Unsafe archive path components");
    ensure!(parts.len()==1 || parts[0]==prefix,"Unexpected archive root");
    if directory {ensure!(parts.len()==1 && parts[0]==prefix,"Unexpected archive directory");return Ok(None);}
    Ok(Some(parts.last().unwrap().to_string()))
}
fn allowed_core_file(name:&str)->bool {
    let name=name.to_ascii_lowercase();
    let stem=name.split('.').next().unwrap_or("");
    if matches!(stem,"con"|"prn"|"aux"|"nul") || (stem.len()==4 && (stem.starts_with("com") || stem.starts_with("lpt")) && matches!(stem.as_bytes()[3],b'1'..=b'9')) {return false;}
    let license=matches!(name.as_str(),"license"|"license.txt"|"copying"|"copying.txt"|"notice"|"notice.txt");
    license || executable_file(&name)
}
fn copy_bounded(input:&mut impl Read,output:&mut impl Write,size:u64,cancel:&CancellationToken)->Result<()> {
    let mut buffer=[0;65536];let mut written=0;
    loop {cancelled(cancel)?;let n=input.read(&mut buffer)?;if n==0 {break;}written+=n as u64;ensure!(written<=size,"Archive member exceeds declared size");output.write_all(&buffer[..n])?;}
    ensure!(written==size,"Archive member is truncated");Ok(())
}
fn extract_core(package:&Path,destination:&Path,version:&str,cancel:&CancellationToken)->Result<()> {
    let (os,arch,ext)=platform()?;let prefix=format!("sing-box-{version}-{os}-{arch}");let mut names=HashSet::new();let mut total=0;
    let mut archive_paths=HashSet::new();
    if ext=="zip" {
        let mut archive=zip::ZipArchive::new(File::open(package)?)?;ensure!(!archive.is_empty() && archive.len()<=256,"Invalid ZIP member count");
        for index in 0..archive.len() {
            cancelled(cancel)?;let mut entry=archive.by_index(index)?;
            ensure!(archive_paths.insert(entry.name().trim_end_matches('/').to_ascii_lowercase()),"Duplicate archive path");
            let mode=entry.unix_mode().unwrap_or(0);let kind=mode&0o170000;
            ensure!(kind==0 || kind==0o100000 || kind==0o040000,"Archive contains a link or special file");
            let Some(name)=archive_name(entry.name(),&prefix,entry.is_dir())? else {ensure!(entry.size()==0,"Directory contains data");continue};
            ensure!(allowed_core_file(&name) && names.insert(name.to_ascii_lowercase()) && entry.size()<=MAX_PACKAGE && (entry.size()<=1024*1024 || entry.size()/entry.compressed_size().max(1)<=200),"Unsafe or duplicate core ZIP member");
            total+=entry.size();ensure!(total<=MAX_EXTRACTED,"Extracted core exceeds size limit");let size=entry.size();
            ensure!(size>0 || !name.eq_ignore_ascii_case("sing-box.exe"),"Empty core executable");
            let mut file=private_file(&destination.join(&name))?;copy_bounded(&mut entry,&mut file,size,cancel)?;file.sync_all()?;
        }
    } else {
        let mut archive=tar::Archive::new(flate2::read::GzDecoder::new(File::open(package)?));let mut count=0;
        for entry in archive.entries()?.raw(true) {
            cancelled(cancel)?;count+=1;ensure!(count<=256,"Too many TAR members");let mut entry=entry?;
            let kind=entry.header().entry_type();ensure!(kind.is_file() || kind.is_dir(),"TAR contains a link or special file");
            let path=std::str::from_utf8(&entry.path_bytes())?.to_owned();
            ensure!(archive_paths.insert(path.trim_end_matches('/').to_ascii_lowercase()),"Duplicate archive path");
            let Some(name)=archive_name(&path,&prefix,kind.is_dir())? else {ensure!(entry.size()==0,"Directory contains data");continue};
            let size=entry.size();ensure!(allowed_core_file(&name) && names.insert(name.to_ascii_lowercase()) && size<=MAX_PACKAGE && (name!="sing-box" || size>0),"Unsafe or duplicate core TAR member");
            total+=size;ensure!(total<=MAX_EXTRACTED && total<=std::fs::metadata(package)?.len().max(1)*200,"Core archive exceeds extraction/ratio limit");
            let target=destination.join(&name);let mut file=private_file(&target)?;copy_bounded(&mut entry,&mut file,size,cancel)?;file.sync_all()?;
            #[cfg(unix)] if name=="sing-box" {use std::os::unix::fs::PermissionsExt;std::fs::set_permissions(&target,std::fs::Permissions::from_mode(0o700))?;}
        }
    }
    ensure!(names.contains(if cfg!(windows){"sing-box.exe"}else{"sing-box"}),"Core archive lacks its executable");Ok(())
}

fn application_name()->Result<String> {
    let arch=if cfg!(target_arch="x86_64"){"x64"}else if cfg!(target_arch="aarch64"){"arm64"}else{bail!("Unsupported application architecture")};
    if cfg!(windows) {ensure!(arch=="x64","No Windows ARM application release format is configured");Ok("MinTunClient.exe".into())}
    else if cfg!(target_os="linux"){Ok(format!("MinTunClient-linux-{arch}.tar.gz"))}
    else if cfg!(target_os="macos"){Ok(format!("MinTunClient-macos-{arch}.tar.gz"))}
    else if cfg!(target_os="android"){Ok(format!("MinTunClient-android-{arch}.apk"))}
    else {bail!("Unsupported application platform")}
}
fn validate_application(release:&ApplicationRelease)->Result<()> {
    ensure!(!version::is_prerelease(&release.version)? && release.name==application_name()?,"Invalid application platform or prerelease");
    validate_asset(&release.version,&release.download_url,&release.sha256,release.size,APP_REPOSITORY,&format!("mintun-v{}",release.version),&release.name)
}
pub async fn application_release(client:&UpdateClient,current:&str,cancel:&CancellationToken)->Result<Option<ApplicationRelease>> {
    version::normalize(current)?;let name=application_name()?;
    let bytes=client.get_bytes(&format!("https://api.github.com/repos/{APP_REPOSITORY}/releases?per_page=30"),4*1024*1024,cancel).await?;
    let releases:Vec<GithubRelease>=serde_json::from_slice(&bytes).map_err(|_|anyhow!("Invalid application release metadata"))?;
    let mut latest:Option<ApplicationRelease>=None;let mut seen=HashSet::new();
    for release in releases {
        cancelled(cancel)?;if release.draft || release.prerelease || release.published_at.as_ref().is_none_or(|s|s.is_empty()) {continue;}
        let Some(text)=release.tag_name.strip_prefix("mintun-v") else {continue};let Ok(normalized)=version::normalize(text) else {continue};
        if text!=normalized || version::is_prerelease(text)? {continue;}
        let mut found=None;
        for asset in release.assets.into_iter().filter(|a|a.name==name) {
            ensure!(found.is_none(),"Duplicate application release assets");
            let sha=digest(&asset)?;
            let candidate=ApplicationRelease {version:text.into(),download_url:asset.browser_download_url,sha256:sha,size:asset.size,name:asset.name};validate_application(&candidate)?;found=Some(candidate);
        }
        if let Some(candidate)=found {
            ensure!(seen.insert(text.split('+').next().unwrap().to_owned()),"Ambiguous application release version");
            if version::compare(text,current)?==Ordering::Greater && latest.as_ref().is_none_or(|r|version::compare(text,&r.version).is_ok_and(|o|o==Ordering::Greater)) {latest=Some(candidate);}
        }
    }
    Ok(latest)
}
pub async fn download_application(client:&UpdateClient,release:&ApplicationRelease,output:&Path,cancel:&CancellationToken,progress:impl Fn(TransferProgress)+Send+Sync)->Result<PathBuf> {
    validate_application(release)?;ensure!(version::compare(&release.version,env!("CARGO_PKG_VERSION"))?==Ordering::Greater,"Refusing an older or current application release");
    private_directory(output)?;let staging=tempfile::Builder::new().prefix(".staging-").tempdir_in(output)?;let package=staging.path().join(&release.name);
    tokio::time::timeout(Duration::from_secs(600),async {
        download(client,&release.download_url,release.size,&release.sha256,&package,cancel,&progress,"Downloading application").await?;
        cancelled(cancel)?;
        let verify_path=package.clone();let verify_version=release.version.clone();let verify_cancel=cancel.child_token();let _cancel_on_drop=verify_cancel.clone().drop_guard();
        tokio::task::spawn_blocking(move ||verify_application(&verify_path,&verify_version,&verify_cancel)).await??;
        let destination=output.join(format!("{}-{}",release.version,uuid::Uuid::new_v4().simple()));
        cancelled(cancel)?;reject_links(output)?;
        // A pending download is only a file. Never execute, install, or replace this application.
        std::fs::rename(staging.path(),&destination)?;
        progress(TransferProgress {received:release.size,total:Some(release.size),message:"Application verified; installation requires your action".into()});
        Ok(destination.join(&release.name))
    }).await.map_err(|_|anyhow!("Application download exceeded ten minutes; current application was not changed"))?
}
#[cfg(any(target_os="android",test))]
fn verify_downloaded_bytes(path:&Path,size:u64,sha256:&str,cancel:&CancellationToken)->Result<()> {
    reject_links(path)?;
    let mut input=File::open(path)?;
    ensure!(input.metadata()?.is_file() && input.metadata()?.len()==size && size<=MAX_PACKAGE,"Скачанный APK изменён или недоступен; скачайте обновление снова");
    let mut hash=Sha256::new();let mut buffer=[0u8;65536];let mut received=0u64;
    loop {
        cancelled(cancel)?;
        let count=input.read(&mut buffer)?;if count==0 {break;}
        received+=count as u64;ensure!(received<=size,"Скачанный APK изменён");
        hash.update(&buffer[..count]);
    }
    ensure!(received==size && hex::encode(hash.finalize()).eq_ignore_ascii_case(sha256),"Скачанный APK изменён; скачайте обновление снова");
    Ok(())
}

#[cfg(target_os="android")]
pub(crate) fn verify_downloaded_application(path:&Path,release:&ApplicationRelease,cancel:&CancellationToken)->Result<()> {
    validate_application(release)?;
    ensure!(path.file_name().and_then(|name|name.to_str())==Some(release.name.as_str()),"APK не соответствует выбранному выпуску");
    verify_downloaded_bytes(path,release.size,&release.sha256,cancel)?;
    verify_application(path,&release.version,cancel)
}

fn verify_application(path:&Path,version:&str,cancel:&CancellationToken)->Result<()> {
    #[cfg(windows)] {verify_windows_application(path,version)?;}
    #[cfg(any(target_os="linux",target_os="macos"))] {verify_unix_application(path,version,cancel)?;}
    #[cfg(target_os="android")] {crate::android::verify_application(path,version)?;}
    let _=(path,version,cancel);Ok(())
}

#[cfg(test)] mod tests {
    use super::*;
    #[cfg(any(target_os="linux",target_os="macos"))]
    #[test]
    #[ignore = "Requires MINTUN_TEST_APPLICATION_ARCHIVE pointing to the actual produced release archive for this OS/architecture"]
    fn packaged_unix_application_passes_runtime_verification() {
        let path=std::path::PathBuf::from(std::env::var_os("MINTUN_TEST_APPLICATION_ARCHIVE")
            .expect("set MINTUN_TEST_APPLICATION_ARCHIVE to the actual produced release archive"));
        verify_unix_application(&path,env!("CARGO_PKG_VERSION"),&CancellationToken::new())
            .unwrap_or_else(|error|panic!("Produced application archive {} failed runtime verification: {error:#}",path.display()));
    }
    #[test] fn export_rejects_replaced_download_even_when_length_is_unchanged() {
        let root=tempfile::tempdir().unwrap();let path=root.path().join("application.apk");
        std::fs::write(&path,b"original").unwrap();
        let expected="0682c5f2076f099c34cfdd15a9e063849ed437a49677e6fcc5b4198c76575be5";
        verify_downloaded_bytes(&path,8,expected,&CancellationToken::new()).unwrap();
        std::fs::write(&path,b"replaced").unwrap();
        assert!(verify_downloaded_bytes(&path,8,expected,&CancellationToken::new()).is_err());
        std::fs::write(&path,b"short").unwrap();
        assert!(verify_downloaded_bytes(&path,8,expected,&CancellationToken::new()).is_err());
        let cancel=CancellationToken::new();cancel.cancel();
        assert!(verify_downloaded_bytes(&path,5,expected,&cancel).is_err());
    }
    #[cfg(not(target_os="android"))]
    #[test] fn exact_official_metadata_rejects_wrong_tag_duplicate_asset_and_missing_digest() {
        let name=core_asset("1.2.3").unwrap();
        let asset=||Asset {name:name.clone(),browser_download_url:format!("https://github.com/SagerNet/sing-box/releases/download/v1.2.3/{name}"),digest:Some(format!("sha256:{}","0".repeat(64))),size:123};
        let release=|tag:&str,assets|GithubRelease {tag_name:tag.into(),draft:false,prerelease:false,published_at:None,assets};
        assert!(exact_core_release(release("v1.2.3",vec![asset()]),"1.2.3").is_ok());
        assert!(exact_core_release(release("v1.2.4",vec![asset()]),"1.2.3").is_err());
        assert!(exact_core_release(release("v1.2.3",vec![asset(),asset()]),"1.2.3").is_err());
        let mut missing=asset();missing.digest=None;
        assert!(exact_core_release(release("v1.2.3",vec![missing]),"1.2.3").is_err());
        assert!(exact_core_release(release("v1.2.3",vec![]),"1.2.3").is_err());
    }
    #[test] fn rejects_unsafe_urls_and_paths() {
        for url in ["http://github.com/a","https://user:pass@github.com/a","https://github.com/a#token"] {assert!(require_https(url).is_err());}
        for path in ["../sing-box","a/../../sing-box","/sing-box","a\\sing-box","a:sing-box","root/name "] {assert!(archive_name(path,"root",false).is_err(),"{path}");}
    }
    #[test] fn rejects_wrong_asset_origin_and_oversize() {
        let sha="00".repeat(32);
        assert!(validate_asset("1.0.0","https://evil.test/x",&sha,1,"SagerNet/sing-box","v1.0.0","x").is_err());
        assert!(validate_asset("1.0.0","https://github.com/SagerNet/sing-box/releases/download/v1.0.0/x",&sha,MAX_PACKAGE+1,"SagerNet/sing-box","v1.0.0","x").is_err());
    }
    #[tokio::test] async fn vpn_transport_authenticates_and_resolves_destination_through_socks() {
        use tokio::io::{AsyncReadExt,AsyncWriteExt};
        let listener=tokio::net::TcpListener::bind(("127.0.0.1",0)).await.unwrap();
        let proxy=ProxyEndpoint {port:listener.local_addr().unwrap().port(),username:"fixture-user".into(),password:"fixture-password".into()};
        let server=tokio::spawn(async move {
            let (mut stream,_)=listener.accept().await.unwrap();
            assert_eq!(stream.read_u8().await.unwrap(),5);
            let count=stream.read_u8().await.unwrap();let mut methods=vec![0;count as usize];stream.read_exact(&mut methods).await.unwrap();assert!(methods.contains(&2));
            stream.write_all(&[5,2]).await.unwrap();
            assert_eq!(stream.read_u8().await.unwrap(),1);
            let count=stream.read_u8().await.unwrap();let mut username=vec![0;count as usize];stream.read_exact(&mut username).await.unwrap();
            let count=stream.read_u8().await.unwrap();let mut password=vec![0;count as usize];stream.read_exact(&mut password).await.unwrap();
            assert_eq!(username,b"fixture-user");assert_eq!(password,b"fixture-password");stream.write_all(&[1,0]).await.unwrap();
            let mut header=[0;4];stream.read_exact(&mut header).await.unwrap();assert_eq!(header,[5,1,0,3]);
            let count=stream.read_u8().await.unwrap();let mut host=vec![0;count as usize];stream.read_exact(&mut host).await.unwrap();assert_eq!(host,b"vpn-only.invalid");
            assert_eq!(stream.read_u16().await.unwrap(),443);
            stream.write_all(&[5,5,0,1,0,0,0,0,0,0]).await.unwrap();
        });
        let client=UpdateClient::new(Some(&proxy)).unwrap();
        assert!(client.get_bytes("https://vpn-only.invalid/fixture",1024,&CancellationToken::new()).await.is_err());
        tokio::time::timeout(Duration::from_secs(3),server).await.unwrap().unwrap();
    }
    #[tokio::test] async fn pre_cancelled_metadata_request_never_connects() {
        let cancel=CancellationToken::new();cancel.cancel();
        assert!(UpdateClient::new(None).unwrap().get_bytes("https://example.invalid/",1024,&cancel).await.is_err());
    }
    #[cfg(not(target_os="android"))]
    fn synthetic_archive(path:&Path,duplicate:bool) {
        let (os,arch,_)=platform().unwrap();let prefix=format!("sing-box-1.0.0-{os}-{arch}");
        #[cfg(windows)] {
            let mut zip=zip::ZipWriter::new(File::create(path).unwrap());
            let options=zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
            zip.start_file(format!("{prefix}/sing-box.exe"),options).unwrap();zip.write_all(b"synthetic executable").unwrap();
            if duplicate {zip.start_file("sing-box.exe",options).unwrap();zip.write_all(b"duplicate").unwrap();}
            zip.finish().unwrap();
        }
        #[cfg(unix)] {
            let gzip=flate2::write::GzEncoder::new(File::create(path).unwrap(),flate2::Compression::default());let mut tar=tar::Builder::new(gzip);
            let bytes=b"synthetic executable";let mut header=tar::Header::new_ustar();header.set_mode(0o700);header.set_size(bytes.len() as u64);header.set_cksum();
            tar.append_data(&mut header,format!("{prefix}/sing-box"),&bytes[..]).unwrap();
            if duplicate {tar.append_data(&mut header,"sing-box",&bytes[..]).unwrap();}
            tar.into_inner().unwrap().finish().unwrap();
        }
    }
    #[cfg(not(target_os="android"))]
    #[test] fn extraction_rejects_duplicates_and_leaves_no_configuration_file() {
        let root=tempfile::tempdir().unwrap();let package=root.path().join("package");let bundle=root.path().join("bundle");std::fs::create_dir(&bundle).unwrap();
        synthetic_archive(&package,true);assert!(extract_core(&package,&bundle,"1.0.0",&CancellationToken::new()).is_err());
        assert!(!bundle.join("config.json").exists());
    }
    #[cfg(not(target_os="android"))]
    #[test] fn extraction_accepts_bounded_expected_platform_layout() {
        let root=tempfile::tempdir().unwrap();let package=root.path().join("package");let bundle=root.path().join("bundle");std::fs::create_dir(&bundle).unwrap();
        synthetic_archive(&package,false);extract_core(&package,&bundle,"1.0.0",&CancellationToken::new()).unwrap();
        assert_eq!(std::fs::read(bundle.join(if cfg!(windows){"sing-box.exe"}else{"sing-box"})).unwrap(),b"synthetic executable");
    }
}

#[cfg(any(target_os="linux",target_os="macos"))]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseManifest {product:String,version:String,os:String,arch:String,executable:String,sha256:String}

#[cfg(any(target_os="linux",target_os="macos"))]
fn verify_unix_application(path:&Path,expected_version:&str,cancel:&CancellationToken)->Result<()> {
    let compressed=std::fs::metadata(path)?.len();
    let mut archive=tar::Archive::new(flate2::read::GzDecoder::new(File::open(path)?));
    let mut names=HashSet::new();let mut total=0u64;let mut manifest=None;let mut binary=None;
    for (index,entry) in archive.entries()?.raw(true).enumerate() {
        cancelled(cancel)?;ensure!(index<8192,"Too many application archive members");
        let mut entry=entry?;let kind=entry.header().entry_type();
        ensure!(kind.is_file() || kind.is_dir(),"Application archive contains a link or special file");
        let name=std::str::from_utf8(&entry.path_bytes())?.to_owned();
        let name=name.trim_end_matches('/').to_owned();
        ensure!(!name.is_empty() && name.len()<=240 && !name.starts_with('/') && !name.contains(['\\',':']) && name.split('/').all(|p|!p.is_empty() && p!="." && p!=".." && !p.ends_with(['.',' '])) && names.insert(name.to_ascii_lowercase()),"Unsafe or duplicate application archive member");
        let size=entry.size();total=total.checked_add(size).ok_or_else(||anyhow!("Application archive size overflow"))?;
        ensure!(size<=MAX_PACKAGE && total<=MAX_EXTRACTED && total<=compressed.max(1)*200,"Application archive exceeds extraction bounds");
        if kind.is_dir(){ensure!(size==0,"Application directory has data");continue;}
        if name=="mintun-release.json" {
            ensure!(manifest.is_none() && size<=16384,"Invalid application release manifest");
            let mut bytes=Vec::with_capacity(size as usize);entry.read_to_end(&mut bytes)?;
            manifest=Some(serde_json::from_slice::<ReleaseManifest>(&bytes).map_err(|_|anyhow!("Invalid application release manifest"))?);
        } else if name=="MinTunClient" || name=="MinTunClient.app/Contents/MacOS/MinTunClient" {
            ensure!(binary.is_none() && size>=64,"Missing or ambiguous application executable");
            let mut hash=Sha256::new();let mut header=Vec::with_capacity(64);let mut received=0u64;let mut buffer=[0;65536];
            loop {cancelled(cancel)?;let n=entry.read(&mut buffer)?;if n==0{break;}received+=n as u64;ensure!(received<=size,"Application member exceeds declared size");hash.update(&buffer[..n]);if header.len()<64{header.extend_from_slice(&buffer[..n.min(64-header.len())]);}}
            ensure!(received==size,"Truncated application executable");verify_unix_binary(&header)?;
            binary=Some((name,hex::encode(hash.finalize())));
        } else {
            // Validate compressed member integrity/size without extracting or retaining its contents.
            copy_bounded(&mut entry,&mut std::io::sink(),size,cancel)?;
        }
    }
    let manifest=manifest.ok_or_else(||anyhow!("Application archive lacks mintun-release.json"))?;
    let (name,sha)=binary.ok_or_else(||anyhow!("Application archive lacks its executable"))?;
    let os=if cfg!(target_os="linux"){"linux"}else{"macos"};
    let arch=if cfg!(target_arch="x86_64"){"x64"}else{"arm64"};
    ensure!(manifest.product=="MinTun Client" && manifest.version==expected_version && manifest.os==os && manifest.arch==arch && manifest.executable==name && manifest.sha256.eq_ignore_ascii_case(&sha),"Application identity, version, architecture or executable hash differs from release");
    Ok(())
}
#[cfg(any(target_os="linux",target_os="macos"))]
fn verify_unix_binary(header:&[u8])->Result<()> {
    ensure!(header.len()>=64,"Truncated native executable");
    #[cfg(target_os="linux")] {
        ensure!(&header[..4]==b"\x7fELF" && header[4]==2 && header[5]==1 && header[6]==1,"Application must be a 64-bit little-endian ELF executable");
        let machine=u16::from_le_bytes([header[18],header[19]]);let kind=u16::from_le_bytes([header[16],header[17]]);
        ensure!(matches!(kind,2|3) && machine==if cfg!(target_arch="x86_64"){62}else{183},"Application ELF architecture/type mismatch");
    }
    #[cfg(target_os="macos")] {
        ensure!(&header[..4]==b"\xcf\xfa\xed\xfe","Application must be a 64-bit Mach-O executable");
        let cpu=u32::from_le_bytes(header[4..8].try_into()?);let kind=u32::from_le_bytes(header[12..16].try_into()?);
        ensure!(kind==2 && cpu==if cfg!(target_arch="x86_64"){0x01000007}else{0x0100000c},"Application Mach-O architecture/type mismatch");
    }
    Ok(())
}
#[cfg(windows)]
fn verify_windows_application(path:&Path,expected_version:&str)->Result<()> {
    use std::{io::{Seek,SeekFrom},os::windows::ffi::OsStrExt};
    let mut file=File::open(path)?;let mut dos=[0;64];file.read_exact(&mut dos)?;
    ensure!(&dos[..2]==b"MZ","Application is not a Windows executable");
    let offset=u32::from_le_bytes(dos[60..64].try_into()?) as u64;
    ensure!(offset>=64 && offset<=16*1024*1024,"Invalid PE header offset");file.seek(SeekFrom::Start(offset))?;
    let mut header=[0;94];file.read_exact(&mut header)?;
    ensure!(&header[..4]==b"PE\0\0" && u16::from_le_bytes(header[4..6].try_into()?)==0x8664 && u16::from_le_bytes(header[24..26].try_into()?)==0x20b && u16::from_le_bytes(header[92..94].try_into()?)==2,"Application must be a Windows x64 GUI executable");
    let flags=u16::from_le_bytes(header[22..24].try_into()?);
    ensure!(flags&2!=0 && flags&0x2000==0,"Application PE must be executable, not a DLL");
    #[link(name="version")] unsafe extern "system" {
        fn GetFileVersionInfoSizeW(path:*const u16,handle:*mut u32)->u32;
        fn GetFileVersionInfoW(path:*const u16,handle:u32,len:u32,data:*mut std::ffi::c_void)->i32;
        fn VerQueryValueW(data:*const std::ffi::c_void,query:*const u16,value:*mut *mut std::ffi::c_void,len:*mut u32)->i32;
    }
    let wide:Vec<u16>=path.as_os_str().encode_wide().chain(Some(0)).collect();
    unsafe {
        let mut ignored=0;let size=GetFileVersionInfoSizeW(wide.as_ptr(),&mut ignored);
        ensure!(size>0 && size<=1024*1024,"Missing or oversized Windows version resource");
        let mut resource=vec![0u8;size as usize];ensure!(GetFileVersionInfoW(wide.as_ptr(),0,size,resource.as_mut_ptr().cast())!=0,"Invalid Windows version resource");
        let contains=|ptr:*const std::ffi::c_void,bytes:usize| (ptr as usize).checked_sub(resource.as_ptr() as usize).is_some_and(|offset|offset<=resource.len() && bytes<=resource.len()-offset);
        let query:Vec<u16>=r"\VarFileInfo\Translation".encode_utf16().chain(Some(0)).collect();let mut translation=std::ptr::null_mut();let mut len=0;
        ensure!(VerQueryValueW(resource.as_ptr().cast(),query.as_ptr(),&mut translation,&mut len)!=0 && len>=4 && !translation.is_null(),"Missing version resource translation");
        ensure!(contains(translation,4),"Version translation is outside its resource");
        let lang=std::ptr::read_unaligned(translation.cast::<u16>());let code=std::ptr::read_unaligned(translation.cast::<u16>().add(1));
        let text=|key:&str|->Result<String>{
            let query:Vec<u16>=format!(r"\StringFileInfo\{lang:04x}{code:04x}\{key}").encode_utf16().chain(Some(0)).collect();let mut ptr=std::ptr::null_mut();let mut count=0;
            ensure!(VerQueryValueW(resource.as_ptr().cast(),query.as_ptr(),&mut ptr,&mut count)!=0 && !ptr.is_null() && count>0 && count<=4096,"Missing application identity resource");
            ensure!((ptr as usize)%2==0 && contains(ptr,count as usize*2),"Version identity string is outside its resource");
            let text=std::slice::from_raw_parts(ptr.cast::<u16>(),count as usize);let end=text.iter().position(|c|*c==0).unwrap_or(text.len());Ok(String::from_utf16(&text[..end])?)
        };
        ensure!(text("ProductName")?=="MinTun Client","Downloaded product is not MinTun Client");
        let actual=text("ProductVersion")?;
        ensure!(version::normalize(&actual)?.split('+').next()==Some(expected_version.split('+').next().unwrap()),"Downloaded application version differs from selected release");
    }
    Ok(())
}
