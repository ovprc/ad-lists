[CmdletBinding()]
param(
    [string]$ArtifactsDirectory = '',
    [string]$CoreArchiveDirectory = '',
    [string]$AndroidSdk = '',
    [string]$JavaHome = '',
    [ValidatePattern('^$|^[0-9a-fA-F]{64}$')][string]$AndroidCertificateSha256 = ''
)
# Read-only verification of actual release outputs. Never compiles, installs or starts a client/core.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $ArtifactsDirectory) { $ArtifactsDirectory = Join-Path $PSScriptRoot '../artifacts' }
if (-not $CoreArchiveDirectory) { $CoreArchiveDirectory = Join-Path $PSScriptRoot '../.tools/core-packages' }
if (-not $AndroidSdk) { $AndroidSdk = Join-Path $PSScriptRoot '../.tools/android-sdk' }
if (-not $JavaHome) { $JavaHome = Join-Path $PSScriptRoot '../.tools/jdk-17.0.21+9' }
Add-Type -AssemblyName System.IO.Compression.FileSystem
Add-Type -AssemblyName System.IO.Compression

# Parse archives without extracting them. Keep only hashes, binary headers and small metadata.
if (-not ('MinTunPackageReader' -as [type])) {
    $source = @'
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

public sealed class MinTunPackageMember {
    public string Name, Sha256, Text;
    public long Size, Mode;
    public bool Directory;
    public byte[] Head;
}
public static class MinTunPackageReader {
    const long MaxFile = 256L * 1024 * 1024, MaxTotal = 1024L * 1024 * 1024;
    static readonly UTF8Encoding Utf8 = new UTF8Encoding(false, true);
    static void Exact(Stream s, byte[] b, int count) {
        int p = 0;
        while (p < count) { int n = s.Read(b, p, count-p); if (n == 0) throw new EndOfStreamException(); p += n; }
    }
    static bool Zero(byte[] b) { foreach (byte c in b) if (c != 0) return false; return true; }
    static string Text(byte[] b, int p, int length) {
        int end = p; while (end < p+length && b[end] != 0) ++end;
        return Utf8.GetString(b, p, end-p);
    }
    static long Octal(byte[] b, int p, int length) {
        string text = Encoding.ASCII.GetString(b,p,length).Trim('\0',' '); long value = 0;
        foreach (char c in text) { if (c < '0' || c > '7') throw new InvalidDataException("Invalid TAR number"); value = checked(value*8+c-'0'); }
        return value;
    }
    static void Name(string name, bool directory, HashSet<string> names) {
        string trimmed = directory ? name.TrimEnd('/') : name;
        if (name.Length == 0 || name.Length > 240 || name.StartsWith("/") || name.IndexOfAny(new char[] {'\\', ':'}) >= 0 || !names.Add(trimmed))
            throw new InvalidDataException("Unsafe/duplicate archive path: " + name);
        foreach (string part in trimmed.Split('/'))
            if (part.Length == 0 || part == "." || part == ".." || part.EndsWith(".") || part.EndsWith(" "))
                throw new InvalidDataException("Unsafe archive component: " + name);
    }
    static MinTunPackageMember Member(Stream s, string name, bool directory, long size, long mode, byte[] buffer) {
        if (size < 0 || size > MaxFile || (directory && size != 0)) throw new InvalidDataException("Invalid member size: " + name);
        MinTunPackageMember m = new MinTunPackageMember { Name=name, Directory=directory, Size=size, Mode=mode, Head=new byte[(int)Math.Min(size,65536)] };
        bool text = !directory && size <= 1048576 && Regex.IsMatch(name, "(?:\\.json|\\.txt|\\.desktop|\\.plist|/LICENSE)$", RegexOptions.IgnoreCase);
        using (MemoryStream metadata = text ? new MemoryStream((int)size) : null)
        using (SHA256 hash = SHA256.Create()) {
            long remaining = size, offset = 0;
            while (remaining > 0) {
                int n = s.Read(buffer,0,(int)Math.Min(remaining,buffer.Length)); if (n == 0) throw new EndOfStreamException();
                hash.TransformBlock(buffer,0,n,buffer,0);
                if (offset < m.Head.Length) Array.Copy(buffer,0,m.Head,(int)offset,(int)Math.Min(n,m.Head.Length-offset));
                if (text) metadata.Write(buffer,0,n);
                remaining -= n; offset += n;
            }
            hash.TransformFinalBlock(buffer,0,0);
            m.Sha256 = BitConverter.ToString(hash.Hash).Replace("-", "").ToLowerInvariant();
            if (text) m.Text = Utf8.GetString(metadata.GetBuffer(),0,(int)metadata.Length).TrimStart('\uFEFF');
        }
        return m;
    }
    public static List<MinTunPackageMember> Read(string path) {
        var result = new List<MinTunPackageMember>(); var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        byte[] buffer = new byte[65536]; long total = 0;
        using (FileStream file = File.OpenRead(path)) {
            if (!path.EndsWith(".tar.gz", StringComparison.OrdinalIgnoreCase)) {
                using (ZipArchive zip = new ZipArchive(file,ZipArchiveMode.Read,true)) {
                    if (zip.Entries.Count == 0 || zip.Entries.Count > 10000) throw new InvalidDataException("Invalid ZIP member count");
                    foreach (ZipArchiveEntry e in zip.Entries) {
                        uint attr = unchecked((uint)e.ExternalAttributes), kind = (attr >> 16) & 0xf000;
                        bool directory = e.FullName.EndsWith("/");
                        if ((attr & 0x400) != 0 || (kind != 0 && kind != 0x8000 && kind != 0x4000) || (kind == 0x4000 && !directory) || (kind == 0x8000 && directory))
                            throw new InvalidDataException("Link/special ZIP member");
                        Name(e.FullName,directory,names);
                        total = checked(total+e.Length); if (total > MaxTotal) throw new InvalidDataException("ZIP too large");
                        using (Stream input = e.Open()) {
                            result.Add(Member(input,e.FullName,directory,e.Length,(attr >> 16) & 0xfff,buffer));
                            if (input.ReadByte() != -1) throw new InvalidDataException("ZIP size mismatch");
                        }
                    }
                }
            } else {
                using (GZipStream input = new GZipStream(file,CompressionMode.Decompress,true)) {
                    byte[] header = new byte[512]; int headers = 0; bool pendingPax = false;
                    while (true) {
                        Exact(input,header,512);
                        if (Zero(header)) {
                            if (pendingPax) throw new InvalidDataException("Orphan PAX header");
                            Exact(input,header,512); if (!Zero(header)) throw new InvalidDataException("Invalid TAR terminator");
                            int trailing = 0, b; while ((b=input.ReadByte()) != -1) if (b != 0 || ++trailing > 1048576) throw new InvalidDataException("Unexpected TAR tail");
                            break;
                        }
                        if (++headers > 10000) throw new InvalidDataException("Too many TAR headers");
                        long sum = 0; for (int i=0;i<512;i++) sum += i >= 148 && i < 156 ? 32 : header[i];
                        if (sum != Octal(header,148,8)) throw new InvalidDataException("TAR checksum mismatch");
                        byte kind=header[156]; long size=Octal(header,124,12), mode=Octal(header,100,8);
                        string name=Text(header,0,100), prefix=Text(header,345,155);
                        if (prefix.Length != 0) name=prefix+"/"+name;
                        if (Text(header,157,100).Length != 0) throw new InvalidDataException("TAR link target");
                        total=checked(total+size); if (total > MaxTotal || size > MaxFile) throw new InvalidDataException("TAR too large");
                        if (kind == (byte)'x') {
                            // package-tar.go emits per-file epoch atime/ctime PAX records only.
                            if (pendingPax || size > 1024) throw new InvalidDataException("Unexpected PAX header");
                            byte[] data=new byte[(int)size]; Exact(input,data,data.Length); int p=0;
                            while (p < data.Length) {
                                int space=Array.IndexOf(data,(byte)' ',p); int length;
                                if (space < 0 || !int.TryParse(Encoding.ASCII.GetString(data,p,space-p),out length) || length <= space-p+1 || length > data.Length-p)
                                    throw new InvalidDataException("Invalid PAX length");
                                string record=Utf8.GetString(data,space+1,p+length-space-1);
                                if (!Regex.IsMatch(record,"\\A(?:atime|ctime|mtime)=0\\n\\z")) throw new InvalidDataException("Unexpected PAX override");
                                p += length;
                            }
                            pendingPax=true;
                        } else {
                            if (kind != 0 && kind != (byte)'0' && kind != (byte)'5') throw new InvalidDataException("Link/special TAR member");
                            bool directory=kind == (byte)'5'; Name(name,directory,names);
                            result.Add(Member(input,name,directory,size,mode,buffer)); pendingPax=false;
                        }
                        int pad=(int)((512-size%512)%512); if (pad != 0) Exact(input,header,pad);
                    }
                }
            }
        }
        if (result.Count == 0) throw new InvalidDataException("Empty archive");
        return result;
    }
}
'@
    if ($PSVersionTable.PSEdition -eq 'Desktop') { Add-Type -TypeDefinition $source -ReferencedAssemblies 'System.dll','System.Core.dll','System.IO.Compression.dll' }
    else { Add-Type -TypeDefinition $source }
}
function Require-File([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Required release artifact/prerequisite missing: $Path" }
    if (((Get-Item -LiteralPath $Path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Release file is a link/reparse point: $Path" }
}
function Read-Members([string]$Path) {
    Require-File $Path
    $members = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($member in [MinTunPackageReader]::Read($Path)) { $members.Add($member.Name, $member) }
    return ,$members
}
function Require-Member($Members, [string]$Name) {
    if (-not $Members.ContainsKey($Name) -or $Members[$Name].Directory -or $Members[$Name].Size -le 0) { throw "Required package member missing/empty: $Name" }
    return $Members[$Name]
}
function Assert-Elf($Member, [int]$Machine) {
    $h = $Member.Head
    if ($h.Length -lt 64 -or $h[0] -ne 127 -or $h[1] -ne 69 -or $h[2] -ne 76 -or $h[3] -ne 70 -or $h[4] -ne 2 -or $h[5] -ne 1 -or [BitConverter]::ToUInt16($h,18) -ne $Machine -or [BitConverter]::ToUInt16($h,16) -notin @(2,3)) { throw "Wrong ELF64 architecture/identity: $($Member.Name)" }
}
function Assert-Pe($Member, [switch]$Client) {
    $h = $Member.Head
    if ($h.Length -lt 64 -or $h[0] -ne 77 -or $h[1] -ne 90) { throw "Not a PE: $($Member.Name)" }
    $p = [BitConverter]::ToInt32($h,60)
    if ($p -lt 64 -or $p -gt $h.Length-264 -or [BitConverter]::ToUInt32($h,$p) -ne 17744 -or [BitConverter]::ToUInt16($h,($p+4)) -ne 34404 -or [BitConverter]::ToUInt16($h,($p+24)) -ne 523) { throw "Not Windows x64 PE32+: $($Member.Name)" }
    if ($Client -and ([BitConverter]::ToUInt16($h,($p+92)) -ne 2 -or ([BitConverter]::ToUInt16($h,($p+22)) -band 8192) -ne 0 -or [BitConverter]::ToUInt32($h,($p+248)) -ne 0)) { throw 'Client must be a native GUI executable, not a DLL or managed runtime.' }
}
function Assert-MachO($Member, [uint32]$Machine, [uint32]$Kind) {
    $h = $Member.Head
    if ($h.Length -lt 32 -or [BitConverter]::ToUInt32($h,0) -ne 4277009103 -or [BitConverter]::ToUInt32($h,4) -ne $Machine -or [BitConverter]::ToUInt32($h,12) -ne $Kind) { throw "Wrong Mach-O64 architecture/type: $($Member.Name)" }
}
$desktop = Join-Path $ArtifactsDirectory 'v2.0.2-rust'
foreach ($platform in @('windows-x64','linux-x64','macos-x64','macos-arm64')) {
    $os,$arch = $platform.Split('-')
    $coreOS = if ($os -eq 'macos') { 'darwin' } else { $os }
    $coreArch = if ($arch -eq 'x64') { 'amd64' } else { 'arm64' }
    $coreDirectory = if ($os -eq 'macos') { 'MinTunClient.app/Contents/Resources/core' } else { 'core' }
    $exe = if ($os -eq 'windows') { 'MinTunClient.exe' } elseif ($os -eq 'macos') { 'MinTunClient.app/Contents/MacOS/MinTunClient' } else { 'MinTunClient' }
    $coreExe = if ($os -eq 'windows') { 'sing-box.exe' } else { 'sing-box' }
    $archiveName = if ($os -eq 'windows') { 'MinTunClient-win-x64.zip' } else { "MinTunClient-$os-$arch.tar.gz" }
    $path = Join-Path $desktop $archiveName
    $members = Read-Members $path
    foreach ($entry in $members.Values) {
        $allowed = $entry.Name -cin @($exe,'mintun-release.json',"$coreDirectory/","$coreDirectory/SOURCE.json","$coreDirectory/$coreExe")
        if ($os -eq 'windows') { $allowed = $allowed -or $entry.Name -cmatch '^core/[A-Za-z0-9][A-Za-z0-9._-]*\.dll$' }
        elseif ($os -eq 'linux') { $allowed = $allowed -or $entry.Name -cin @('mintun.desktop','mintun.png') -or $entry.Name -cmatch '^core/[A-Za-z0-9][A-Za-z0-9._-]*\.so(?:\.[0-9]+)*$' }
        else {
            $allowed = $allowed -or $entry.Name -cin @('MinTunClient.app/','MinTunClient.app/Contents/','MinTunClient.app/Contents/MacOS/','MinTunClient.app/Contents/Resources/','MinTunClient.app/Contents/_CodeSignature/','MinTunClient.app/Contents/Info.plist','MinTunClient.app/Contents/Resources/mintun.icns','MinTunClient.app/Contents/_CodeSignature/CodeResources') -or $entry.Name -cmatch '^MinTunClient\.app/Contents/Resources/core/[A-Za-z0-9][A-Za-z0-9._-]*\.dylib$'
        }
        if (-not $allowed -or ($entry.Directory -and $os -ne 'macos' -and $entry.Name -cne 'core/')) { throw "Unexpected/private/runtime file in ${archiveName}: $($entry.Name)" }
        if ($os -ne 'windows') {
            $mode = if ($entry.Directory -or $entry.Name -cin @($exe,"$coreDirectory/$coreExe")) { 493 } else { 420 }
            if ($entry.Mode -ne $mode) { throw "Incorrect Unix mode for $($entry.Name): $($entry.Mode)" }
        }
    }
    $client = Require-Member $members $exe
    $core = Require-Member $members "$coreDirectory/$coreExe"
    $manifest = (Require-Member $members 'mintun-release.json').Text | ConvertFrom-Json
    if ($manifest.product -cne 'MinTun Client' -or $manifest.version -cne '2.0.2' -or $manifest.os -cne $os -or $manifest.arch -cne $arch -or $manifest.executable -cne $exe -or $manifest.sha256 -cne $client.Sha256) { throw "Wrong release identity or executable digest: $archiveName" }
    $provenance = (Require-Member $members "$coreDirectory/SOURCE.json").Text | ConvertFrom-Json
    $extension = if ($os -eq 'windows') { 'zip' } else { 'tar.gz' }
    $officialName = "sing-box-1.15.0-alpha.13-$coreOS-$coreArch.$extension"
    $officialUrl = "https://github.com/SagerNet/sing-box/releases/download/v1.15.0-alpha.13/$officialName"
    $officialPath = Join-Path $CoreArchiveDirectory $officialName
    Require-File $officialPath
    if ($provenance.version -cne '1.15.0-alpha.13' -or $provenance.source -cne $officialUrl -or $provenance.sha256 -cnotmatch '^[0-9a-f]{64}$' -or $provenance.sha256 -cne (Get-FileHash -LiteralPath $officialPath -Algorithm SHA256).Hash.ToLowerInvariant()) { throw "Wrong bundled core provenance/digest: $archiveName" }
    $official = Read-Members $officialPath
    $expected = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($entry in $official.Values) {
        if ($entry.Directory) { continue }
        $prefix = "sing-box-1.15.0-alpha.13-$coreOS-$coreArch/"
        $name = $entry.Name
        if ($name.StartsWith($prefix, [StringComparison]::Ordinal)) { $name = $name.Substring($prefix.Length) }
        if ($name.Contains('/')) { throw "Unexpected official core layout: $($entry.Name)" }
        if ($name -ine 'sing-box' -and $name -notmatch '\.(exe|dll|dylib)$|\.so(\.[0-9]+)*$') { continue }
        $expected.Add("$coreDirectory/$name", $entry)
    }
    foreach ($name in $expected.Keys) {
        $entry = Require-Member $members $name
        if ($entry.Sha256 -cne $expected[$name].Sha256) { throw "Bundled core differs from verified official archive: $name" }
    }
    foreach ($entry in $members.Values) {
        if (-not $entry.Directory -and $entry.Name.StartsWith("$coreDirectory/", [StringComparison]::Ordinal) -and $entry.Name -cne "$coreDirectory/SOURCE.json" -and -not $expected.ContainsKey($entry.Name)) { throw "Extra bundled core file: $($entry.Name)" }
    }
    if ($os -eq 'windows') {
        Assert-Pe $client -Client
        Assert-Pe $core
        $standalone = Join-Path $desktop 'MinTunClient.exe'
        Require-File $standalone
        if ((Get-FileHash -LiteralPath $standalone -Algorithm SHA256).Hash.ToLowerInvariant() -cne $client.Sha256) { throw 'Standalone Windows EXE differs from release ZIP.' }
        $identity = [Diagnostics.FileVersionInfo]::GetVersionInfo([IO.Path]::GetFullPath($standalone))
        if ($identity.ProductName -cne 'MinTun Client' -or $identity.ProductMajorPart -ne 2 -or $identity.ProductMinorPart -ne 0 -or $identity.ProductBuildPart -ne 2 -or $identity.ProductPrivatePart -ne 0) { throw 'Wrong Windows executable product/version resource.' }
    } elseif ($os -eq 'linux') {
        Assert-Elf $client 62
        Assert-Elf $core 62
        $null = Require-Member $members 'mintun.desktop'
        $null = Require-Member $members 'mintun.png'
    } else {
        $machine = if ($arch -eq 'x64') { 16777223 } else { 16777228 }
        Assert-MachO $client $machine 2
        Assert-MachO $core $machine 2
        foreach ($entry in $members.Values) {
            if (-not $entry.Directory -and $entry.Name.EndsWith('.dylib', [StringComparison]::Ordinal)) { Assert-MachO $entry $machine 6 }
        }
        $plist = [Xml.XmlDocument]::new()
        $plist.XmlResolver = $null
        $plist.LoadXml((Require-Member $members 'MinTunClient.app/Contents/Info.plist').Text)
        $identity = @{}
        $nodes = $plist.plist.dict.ChildNodes
        for ($i = 0; $i -lt $nodes.Count; $i += 2) {
            if ($nodes[$i].Name -cne 'key' -or $i + 1 -ge $nodes.Count -or $identity.ContainsKey($nodes[$i].InnerText)) { throw 'Invalid/duplicate macOS bundle identity key.' }
            $identity.Add($nodes[$i].InnerText, $nodes[$i+1].InnerText)
        }
        if ($identity.CFBundleIdentifier -cne 'app.mintun.client' -or $identity.CFBundleExecutable -cne 'MinTunClient' -or $identity.CFBundlePackageType -cne 'APPL' -or $identity.CFBundleVersion -cne '2.0.2' -or $identity.CFBundleShortVersionString -cne '2.0.2') { throw 'Wrong macOS app bundle identity/version.' }
        $null = Require-Member $members 'MinTunClient.app/Contents/_CodeSignature/CodeResources'
    }
    Get-FileHash -LiteralPath $path -Algorithm SHA256
}

$aapt = Join-Path $AndroidSdk 'build-tools/35.0.0/aapt2.exe'
$apksigner = Join-Path $AndroidSdk 'build-tools/35.0.0/apksigner.bat'
$zipalign = Join-Path $AndroidSdk 'build-tools/35.0.0/zipalign.exe'
foreach ($tool in @($aapt,$apksigner,$zipalign,(Join-Path $JavaHome 'bin/java.exe'))) { Require-File $tool }
$previousJava = $env:JAVA_HOME
$certificate = $null
try {
    $env:JAVA_HOME = [IO.Path]::GetFullPath($JavaHome)
    foreach ($abi in @(@('arm64','arm64-v8a',183),@('x64','x86_64',62))) {
        $path = Join-Path $ArtifactsDirectory "android/MinTunClient-android-$($abi[0]).apk"
        $members = Read-Members $path
        $null = Require-Member $members 'AndroidManifest.xml'
        $null = Require-Member $members 'classes.dex'
        $null = Require-Member $members 'resources.arsc'
        foreach ($entry in $members.Values) {
            # Android framework resources/META-INF have generated names; confine each to its format.
            $allowed = $entry.Name -cin @('AndroidManifest.xml','resources.arsc','assets/libbox-build.json','assets/libbox-provenance.json') -or
                $entry.Name -cmatch '^classes(?:[2-9]|[1-9][0-9]+)?\.dex$' -or $entry.Name -cmatch '^res/[A-Za-z0-9_./+-]+$' -or
                $entry.Name -cmatch '^META-INF/[A-Za-z0-9_./+-]+$' -or $entry.Name -cin @("lib/$($abi[1])/libmintun_client.so", "lib/$($abi[1])/libbox.so")
            $private = $entry.Name -match '(?i)(?:^|/)(?:\.private|private|android-signing|client\.mintun|state\.bin|publisher\.key|credentials\.dpapi|recovery\.json|configTUN\.json)(?:/|$)|\.(?:p12|pfx|jks|keystore|log)$'
            if (-not $allowed -or $private -or $entry.Directory) { throw "Unexpected/private APK member: $($entry.Name)" }
        }
        foreach ($library in @('libmintun_client.so','libbox.so')) { Assert-Elf (Require-Member $members "lib/$($abi[1])/$library") $abi[2] }
        foreach ($name in @('assets/libbox-build.json','assets/libbox-provenance.json')) { $null = Require-Member $members $name }
        $provenance = $members['assets/libbox-provenance.json'].Text | ConvertFrom-Json
        $build = $members['assets/libbox-build.json'].Text | ConvertFrom-Json
        if ($provenance.tag -cne 'v1.15.0-alpha.13' -or $build.tag -cne $provenance.tag -or $provenance.commit -cne '824dbcfb4dd0a95921840b1737b950cde590241e' -or $build.commit -cne $provenance.commit -or $provenance.archiveSha256 -cne '29047987ed69ba790f2ae4eec62abf41bd1619d093af071f505b4ba081e06b44' -or $build.sourceArchiveSha256 -cne $provenance.archiveSha256) { throw 'Incorrect embedded Android libbox provenance.' }
        $badging = @(& $aapt dump badging $path)
        if ($LASTEXITCODE -ne 0) { throw 'aapt2 could not inspect release APK.' }
        $identity = @($badging | Where-Object { $_ -cmatch '^package: ' })
        if ($identity.Count -ne 1 -or $identity[0] -cnotmatch "^package: name='app\.mintun\.client' versionCode='20002' versionName='2\.0\.2'(?: |$)" -or ($badging -join "`n") -match '(?m)^application-debuggable' -or ($badging -join "`n") -cnotmatch ("(?m)^native-code: '" + [regex]::Escape($abi[1]) + "'\s*$")) { throw 'Wrong APK package/version/ABI or debuggable release.' }
        $signature = @(& $apksigner verify --verbose --print-certs $path)
        if ($LASTEXITCODE -ne 0) { throw 'APK signature verification failed.' }
        $signers = [regex]::Matches(($signature -join "`n"), '(?m)^Signer #[0-9]+ certificate SHA-256 digest:\s*([a-fA-F0-9]{64})\s*$')
        if ($signers.Count -ne 1 -or ($signature -join "`n") -match 'CN=Android Debug') { throw 'Expected a single non-debug permanent APK signer.' }
        $fingerprint = $signers[0].Groups[1].Value.ToLowerInvariant()
        if ($certificate -and $certificate -cne $fingerprint) { throw 'Android ABI APK signing identities differ.' }
        if ($AndroidCertificateSha256 -and $fingerprint -cne $AndroidCertificateSha256.ToLowerInvariant()) { throw 'APK signer does not match the expected permanent certificate.' }
        $certificate = $fingerprint
        & $zipalign -c -P 16 4 $path
        if ($LASTEXITCODE -ne 0) { throw 'APK zip alignment failed.' }
        Require-File ($path + '.sha256')
        $digest = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        $expectedDigest = "$digest  $([IO.Path]::GetFileName($path))"
        if ([IO.File]::ReadAllText([IO.Path]::GetFullPath($path + '.sha256')).Trim() -cne $expectedDigest) { throw 'APK checksum sidecar does not match the actual release.' }
        Get-FileHash -LiteralPath $path -Algorithm SHA256
    }
} finally { $env:JAVA_HOME = $previousJava }
Write-Output "PASS: real Rust Windows/Linux packages and both Android release APKs; Android signer SHA256 $certificate. No client/core was executed or installed."
