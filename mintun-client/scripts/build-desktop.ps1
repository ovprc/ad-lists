param(
    [string]$Target = '',
    [string]$CoreVersion = '1.15.0-alpha.13',
    [string]$OutputDirectory = '',
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Release',
    [switch]$SkipCompile
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if ($SkipCompile) { throw '-SkipCompile cannot prove the embedded core trust manifest; release packaging requires a fresh Cargo build.' }
if ($CoreVersion -cnotmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$') {
    throw 'CoreVersion must be an exact normalized release version.'
}

function Assert-NoLinks([string]$Path) {
    $current = [IO.Path]::GetFullPath($Path)
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $item.LinkType) {
                throw "Build paths may not traverse links or reparse points: $current"
            }
        }
        $parent = [IO.Path]::GetDirectoryName($current)
        if ($parent -eq $current) { break }
        $current = $parent
    }
}

function New-PrivateDirectory([string]$Path) {
    Assert-NoLinks $Path
    if (Test-Path -LiteralPath $Path) { throw "Build staging already exists: $Path" }
    if ($env:OS -eq 'Windows_NT') {
        $acl = [Security.AccessControl.DirectorySecurity]::new()
        $acl.SetAccessRuleProtection($true, $false)
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $acl.SetOwner($identity)
        foreach ($sid in @($identity, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'), [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))) {
            $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
        }
        if ($PSVersionTable.PSEdition -eq 'Desktop') {
            [IO.Directory]::CreateDirectory($Path, $acl) | Out-Null
        } else {
            [IO.FileSystemAclExtensions]::Create([IO.DirectoryInfo]::new($Path), $acl)
        }
    } else {
        & /bin/mkdir -m 700 -- $Path
        if ($LASTEXITCODE -ne 0) { throw "Unable to create private staging: $Path" }
    }
}

# Parse members ourselves: invoking tar before checking types/paths can materialize links.
# These bounds and the flat bundle allowlist mirror native/updates.rs.
Add-Type -AssemblyName System.IO.Compression
if (-not ('MinTunBuildArchive' -as [type])) {
    $archiveSource = @'
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;

public static class MinTunBuildArchive {
    const long MaxFile = 256L * 1024 * 1024;
    const long MaxTotal = 512L * 1024 * 1024;
    static readonly UTF8Encoding Utf8 = new UTF8Encoding(false, true);
    sealed class Members {
        readonly string root, executable, destination;
        readonly HashSet<string> paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        readonly HashSet<string> names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        long total;
        int count;
        public Members(string root, string executable, string destination) {
            this.root = root; this.executable = executable; this.destination = destination;
        }
        public string Member(string path, bool directory, long size) {
            if (++count > 256 || path.Length > 240 || path.StartsWith("/") || path.IndexOfAny(new char[] {'\\', ':'}) >= 0)
                throw new InvalidDataException("Unsafe archive path/count");
            string trimmed = path.EndsWith("/") ? path.Substring(0, path.Length - 1) : path;
            if (!paths.Add(trimmed)) throw new InvalidDataException("Duplicate/case-colliding archive path");
            string[] parts = trimmed.Split('/');
            if (parts.Length < 1 || parts.Length > 2 || (parts.Length == 2 && parts[0] != root))
                throw new InvalidDataException("Unexpected archive root");
            foreach (string part in parts)
                if (part.Length == 0 || part == "." || part == ".." || part.EndsWith(".") || part.EndsWith(" "))
                    throw new InvalidDataException("Unsafe archive component");
            if (directory) {
                if (parts.Length != 1 || parts[0] != root || size != 0)
                    throw new InvalidDataException("Unexpected archive directory");
                return null;
            }
            string name = parts[parts.Length - 1];
            string lower = name.ToLowerInvariant();
            string stem = lower.Split('.')[0];
            bool reserved = Regex.IsMatch(stem, "^(con|prn|aux|nul|com[1-9]|lpt[1-9])$");
            bool license = Regex.IsMatch(lower, "^(license|copying|notice)(\\.txt)?$");
            bool dependency = Regex.IsMatch(lower, "\\.(dll|dylib)$|\\.so(\\.[0-9]+)*$");
            if (reserved || !Regex.IsMatch(name, "^[A-Za-z0-9][A-Za-z0-9._-]*$") ||
                !(license || name == executable || dependency) || !names.Add(name))
                throw new InvalidDataException("Unexpected/duplicate core member: " + name);
            if (size < 0 || size > MaxFile || (name == executable && size == 0) || (total += size) > MaxTotal)
                throw new InvalidDataException("Core member exceeds extraction bounds");
            return Path.Combine(destination, name);
        }
        public void Complete() {
            if (!names.Contains(executable)) throw new InvalidDataException("Official archive lacks core executable");
        }
    }
    static void Exact(Stream input, byte[] buffer, int count) {
        int offset = 0;
        while (offset < count) {
            int n = input.Read(buffer, offset, count - offset);
            if (n == 0) throw new EndOfStreamException("Truncated archive");
            offset += n;
        }
    }
    static void Copy(Stream input, string path, long size, byte[] buffer) {
        using (FileStream output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None)) {
            while (size > 0) {
                int n = input.Read(buffer, 0, (int)Math.Min(size, buffer.Length));
                if (n == 0) throw new EndOfStreamException("Truncated member");
                output.Write(buffer, 0, n); size -= n;
            }
            output.Flush(true);
        }
    }
    static string Text(byte[] header, int offset, int length) {
        int end = offset;
        while (end < offset + length && header[end] != 0) ++end;
        return Utf8.GetString(header, offset, end - offset);
    }
    static long Octal(byte[] header, int offset, int length) {
        string text = Encoding.ASCII.GetString(header, offset, length).Trim('\0', ' ');
        if (text.Length == 0) return 0;
        long value = 0;
        foreach (char c in text) {
            if (c < '0' || c > '7') throw new InvalidDataException("Invalid TAR number");
            value = checked(value * 8 + c - '0');
        }
        return value;
    }
    static bool Zero(byte[] block) {
        foreach (byte b in block) if (b != 0) return false;
        return true;
    }
    public static void Extract(string archive, string destination, string root, string executable, bool zip) {
        Members members = new Members(root, executable, destination);
        byte[] buffer = new byte[65536];
        using (FileStream file = File.OpenRead(archive)) {
            if (zip) {
                using (ZipArchive entries = new ZipArchive(file, ZipArchiveMode.Read, true)) {
                    if (entries.Entries.Count == 0 || entries.Entries.Count > 256)
                        throw new InvalidDataException("Invalid ZIP member count");
                    foreach (ZipArchiveEntry entry in entries.Entries) {
                        uint attributes = unchecked((uint)entry.ExternalAttributes);
                        uint kind = (attributes >> 16) & 0xf000;
                        bool directory = entry.FullName.EndsWith("/");
                        if ((attributes & 0x400) != 0 || (kind != 0 && kind != 0x8000 && kind != 0x4000) ||
                            (kind == 0x4000 && !directory) || (kind == 0x8000 && directory))
                            throw new InvalidDataException("ZIP contains a link or special file");
                        string path = members.Member(entry.FullName, directory, entry.Length);
                        if (path == null) continue;
                        if (entry.Length > 1024 * 1024 && entry.Length / Math.Max(1, entry.CompressedLength) > 200)
                            throw new InvalidDataException("ZIP member compression ratio exceeds limit");
                        using (Stream input = entry.Open()) {
                            Copy(input, path, entry.Length, buffer);
                            if (input.ReadByte() != -1) throw new InvalidDataException("ZIP member exceeds declared size");
                        }
                    }
                }
            } else {
                using (GZipStream input = new GZipStream(file, CompressionMode.Decompress, true)) {
                    byte[] header = new byte[512];
                    long expanded = 0;
                    while (true) {
                        Exact(input, header, 512);
                        expanded += 512;
                        if (Zero(header)) {
                            Exact(input, header, 512);
                            if (!Zero(header)) throw new InvalidDataException("Invalid TAR terminator");
                            int trailing = 0, b;
                            while ((b = input.ReadByte()) != -1)
                                if (b != 0 || ++trailing > 1024 * 1024) throw new InvalidDataException("Unexpected TAR trailing data");
                            break;
                        }
                        long sum = 0;
                        for (int i = 0; i < header.Length; ++i) sum += (i >= 148 && i < 156) ? 32 : header[i];
                        if (sum != Octal(header, 148, 8)) throw new InvalidDataException("TAR header checksum mismatch");
                        byte kind = header[156];
                        if (kind != 0 && kind != (byte)'0' && kind != (byte)'5')
                            throw new InvalidDataException("TAR contains a link or special/extended header");
                        if (Text(header, 157, 100).Length != 0) throw new InvalidDataException("Unexpected TAR link target");
                        string name = Text(header, 0, 100);
                        string prefix = Text(header, 345, 155);
                        if (prefix.Length != 0) name = prefix + "/" + name;
                        long size = Octal(header, 124, 12);
                        string path = members.Member(name, kind == (byte)'5', size);
                        expanded = checked(expanded + size);
                        if (expanded > MaxTotal + 256 * 1024 || expanded > file.Length * 200)
                            throw new InvalidDataException("TAR extraction/ratio limit exceeded");
                        if (path != null) Copy(input, path, size, buffer);
                        int padding = (int)((512 - size % 512) % 512);
                        if (padding != 0) Exact(input, header, padding);
                    }
                }
            }
        }
        members.Complete();
    }
}
'@
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        Add-Type -TypeDefinition $archiveSource -ReferencedAssemblies 'System.dll','System.Core.dll','System.IO.Compression.dll'
    } else {
        Add-Type -TypeDefinition $archiveSource
    }
}

$root = Split-Path $PSScriptRoot -Parent
$tools = Join-Path $root '.tools'
if (Test-Path (Join-Path $tools 'cargo\bin\cargo.exe')) {
    $env:CARGO_HOME = Join-Path $tools 'cargo'
    $env:RUSTUP_HOME = Join-Path $tools 'rustup'
    $env:PATH = "$(Join-Path $env:CARGO_HOME 'bin');$(Join-Path $tools 'w64devkit\bin');$(Join-Path $tools 'zig\ziglang');$env:PATH"
    $hostLibraries = Join-Path (& rustc --print sysroot) 'lib/rustlib/x86_64-pc-windows-gnu/lib/self-contained'
    if (Test-Path -LiteralPath $hostLibraries) {
        $env:LIBRARY_PATH = "$hostLibraries;$env:LIBRARY_PATH"
    }
}
$cargo = (Get-Command cargo -ErrorAction Stop).Source
$curlName = if ($env:OS -eq 'Windows_NT') { 'curl.exe' } else { 'curl' }
$curl = (Get-Command $curlName -CommandType Application -ErrorAction Stop).Source
if (-not $Target) {
    $hostLine = & rustc -vV | Where-Object { $_ -like 'host: *' }
    $Target = $hostLine.Substring(6)
}
if ($Target -match '^(x86_64|aarch64)-apple-darwin$') {
    $osName = 'macos'; $arch = if ($Matches[1] -eq 'aarch64') { 'arm64' } else { 'x64' }
    $coreOS = 'darwin'; $exeName = 'MinTunClient'; $coreExe = 'sing-box'; $extension = 'tar.gz'
} elseif ($Target -match '^(x86_64|aarch64)-unknown-linux-(gnu|musl)(\.[0-9]+\.[0-9]+)?$') {
    $osName = 'linux'; $arch = if ($Matches[1] -eq 'aarch64') { 'arm64' } else { 'x64' }
    $coreOS = 'linux'; $exeName = 'MinTunClient'; $coreExe = 'sing-box'; $extension = 'tar.gz'
} elseif ($Target -eq 'x86_64-pc-windows-gnu' -or $Target -eq 'x86_64-pc-windows-msvc') {
    $osName = 'windows'; $arch = 'x64'; $coreOS = 'windows'; $exeName = 'MinTunClient.exe'; $coreExe = 'sing-box.exe'; $extension = 'zip'
} else { throw "Unsupported desktop target: $Target" }
if ($Configuration -eq 'Debug' -and $osName -ne 'windows') { throw 'Debug test bundles currently support Windows only.' }
$version = '2.0.2'
if (-not $OutputDirectory) {
    $OutputDirectory = if ($Configuration -eq 'Debug') { Join-Path $root 'dist\MinTun-Windows-dev' } else { Join-Path $root "artifacts\v$version-rust" }
}
$output = [IO.Path]::GetFullPath($OutputDirectory)
$finalPackage = Join-Path $output "$osName-$arch"
$staging = Join-Path $output ".$osName-$arch-stage-$([Guid]::NewGuid().ToString('N'))"
$package = Join-Path $staging 'payload'
$previousTrustManifest = [Environment]::GetEnvironmentVariable('MINTUN_TRUSTED_CORE_MANIFEST', 'Process')
$previousFontconfigDlopen = [Environment]::GetEnvironmentVariable('RUST_FONTCONFIG_DLOPEN', 'Process')
$previousCrossEnvironment = @{}
foreach ($name in @('PKG_CONFIG','PKG_CONFIG_ALLOW_CROSS','PKG_CONFIG_SYSROOT_DIR','PKG_CONFIG_LIBDIR','MINTUN_LINUX_SYSROOT','MINTUN_LINUX_TRIPLET')) {
    $previousCrossEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
Assert-NoLinks $output
[IO.Directory]::CreateDirectory($output) | Out-Null
New-PrivateDirectory $staging
Push-Location $root
try {
    if ($osName -eq 'linux') {
        $env:RUST_FONTCONFIG_DLOPEN = $null
        if ($env:OS -eq 'Windows_NT') {
            $sysroot = Join-Path $tools 'linux-sysroot'
            $triplet = if ($arch -eq 'x64') { 'x86_64-linux-gnu' } else { 'aarch64-linux-gnu' }
            $pkgconfig = Join-Path $sysroot "usr/lib/$triplet/pkgconfig"
            if (!(Test-Path (Join-Path $pkgconfig 'fontconfig.pc'))) {
                throw 'Linux cross-build requires the verified Linux fontconfig/freetype development sysroot in .tools/linux-sysroot; native Linux builds use distribution pkg-config.'
            }
            $env:PKG_CONFIG_ALLOW_CROSS = '1'
            $env:PKG_CONFIG_SYSROOT_DIR = $sysroot
            $env:PKG_CONFIG_LIBDIR = "$pkgconfig;$(Join-Path $sysroot 'usr/share/pkgconfig')"
            $env:MINTUN_LINUX_SYSROOT = $sysroot.Replace('\','/')
            $env:MINTUN_LINUX_TRIPLET = $triplet
            $env:PKG_CONFIG = Join-Path $PSScriptRoot 'pkg-config-linux.cmd'
        }
    }
    New-PrivateDirectory $package
    $coreBundle = Join-Path $staging 'official-core'
    New-PrivateDirectory $coreBundle
    $coreArch = if ($arch -eq 'x64') { 'amd64' } else { 'arm64' }
    $assetName = "sing-box-$CoreVersion-$coreOS-$coreArch.$extension"
    $archiveRoot = "sing-box-$CoreVersion-$coreOS-$coreArch"
    $metadata = Join-Path $staging 'official-release.json'
    & $curl --fail --silent --show-error --proto '=https' --connect-timeout 30 --max-time 120 --max-filesize 4194304 --header 'User-Agent: MinTun-build/2.0' --header 'Accept: application/vnd.github+json' --output $metadata "https://api.github.com/repos/SagerNet/sing-box/releases/tags/v$CoreVersion"
    if ($LASTEXITCODE -ne 0) { throw 'Official core release metadata request failed.' }
    $release = Get-Content -LiteralPath $metadata -Raw | ConvertFrom-Json
    if ($release.draft -or $release.tag_name -cne "v$CoreVersion") { throw 'Official core release tag does not match the selected version.' }
    $assets = @($release.assets | Where-Object { $_.name -ceq $assetName })
    if ($assets.Count -ne 1 -or $assets[0].digest -cnotmatch '^sha256:([0-9a-fA-F]{64})$') {
        throw "Official core artifact/digest missing or duplicated: $assetName"
    }
    $expectedHash = $Matches[1].ToLowerInvariant()
    $asset = $assets[0]
    $expectedUrl = "https://github.com/SagerNet/sing-box/releases/download/v$CoreVersion/$assetName"
    if ($asset.browser_download_url -cne $expectedUrl -or $asset.size -le 0 -or $asset.size -gt 268435456 -or [long]$asset.size -ne $asset.size) {
        throw 'Invalid official core asset URL/size.'
    }
    $archive = Join-Path $staging $assetName
    $cacheDirectory = Join-Path $tools 'core-packages'
    $cachedArchive = Join-Path $cacheDirectory $assetName
    Assert-NoLinks $cachedArchive
    if (Test-Path -LiteralPath $cachedArchive -PathType Leaf) {
        if ((Get-Item -LiteralPath $cachedArchive).Length -ne $asset.size) { throw 'Cached core archive differs from fresh official release size.' }
        # Hash and extract one private snapshot, never the mutable archive/cache directory.
        [IO.File]::Copy($cachedArchive, $archive, $false)
    } else {
        & $curl --fail --silent --show-error --location --max-redirs 6 --proto '=https' --proto-redir '=https' --retry 2 --connect-timeout 30 --max-time 1200 --max-filesize $asset.size --output $archive $expectedUrl
        if ($LASTEXITCODE -ne 0) { throw 'Core download failed.' }
    }
    if ((Get-Item -LiteralPath $archive).Length -ne $asset.size -or (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expectedHash) {
        throw 'Core archive does not match fresh official release size/SHA256.'
    }
    [MinTunBuildArchive]::Extract($archive, $coreBundle, $archiveRoot, $coreExe, $extension -eq 'zip')
    $coreFiles = @(Get-ChildItem -LiteralPath $coreBundle -File)
    $trustedFiles = [ordered]@{}
    foreach ($file in ($coreFiles | Sort-Object Name)) {
        if ($file.Name -ieq 'sing-box' -or $file.Name -match '\.(exe|dll|dylib)$|\.so(\.[0-9]+)*$') {
            $trustedFiles[$file.Name] = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
    $trustManifest = Join-Path $staging 'trusted-core.json'
    $trustedCore = [ordered]@{
        version = $CoreVersion
        os = $osName
        arch = $(if ($arch -eq 'x64') { 'x86_64' } else { 'aarch64' })
        asset_sha256 = $expectedHash
        files = $trustedFiles
    }
    [IO.File]::WriteAllText($trustManifest, ($trustedCore | ConvertTo-Json -Depth 4), [Text.UTF8Encoding]::new($false))
    # Keep only an archive cache; every future build reauthenticates against live official metadata.
    Assert-NoLinks $cacheDirectory
    [IO.Directory]::CreateDirectory($cacheDirectory) | Out-Null
    if (-not (Test-Path -LiteralPath $cachedArchive)) { [IO.File]::Copy($archive, $cachedArchive, $false) }
    $env:MINTUN_TRUSTED_CORE_MANIFEST = $trustManifest
    $subcommand = if ($osName -eq 'linux' -and $env:OS -eq 'Windows_NT') { 'zigbuild' } else { 'build' }
    $cargoArguments = @($subcommand, '--locked', '--bin', 'MinTunClient', '--target', $Target, '--target-dir', (Join-Path $root 'target'))
    if ($Configuration -eq 'Release') { $cargoArguments += '--release' }
    & $cargo @cargoArguments
    if ($LASTEXITCODE -ne 0) { throw "Rust build failed for $Target" }
    $rustTarget = $Target.Split('.')[0]
    $profile = $Configuration.ToLowerInvariant()
    $binary = Join-Path $root "target\$rustTarget\$profile\$exeName"
    if (-not (Test-Path $binary)) { throw "Built client not found: $binary" }
    if ($osName -eq 'macos') {
        $relativeExe = 'MinTunClient.app/Contents/MacOS/MinTunClient'
        $binaryDir = Join-Path $package 'MinTunClient.app\Contents\MacOS'
        $resources = Join-Path $package 'MinTunClient.app\Contents\Resources'
        New-Item -ItemType Directory -Force -Path $binaryDir,$resources | Out-Null
        Copy-Item $binary (Join-Path $binaryDir $exeName) -Force
        Copy-Item (Join-Path $root 'assets\mintun.icns') $resources -Force
        @"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>app.mintun.client</string>
<key>CFBundleName</key><string>MinTun</string>
<key>CFBundleDisplayName</key><string>MinTun</string>
<key>CFBundleExecutable</key><string>MinTunClient</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>$version</string>
<key>CFBundleVersion</key><string>$version</string>
<key>CFBundleIconFile</key><string>mintun.icns</string>
<key>LSMinimumSystemVersion</key><string>12.0</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
"@ | Set-Content (Join-Path $package 'MinTunClient.app\Contents\Info.plist') -Encoding UTF8
    } else {
        $relativeExe = $exeName
        $binaryDir = $package
        Copy-Item $binary (Join-Path $package $exeName) -Force
    }
    # Bundled core is an authenticated staging payload, not nested application code.
    # Resources preserves official bytes/signatures without unsupported MacOS subdirectories.
    $coreOut = if ($osName -eq 'macos') { Join-Path $resources 'core' } else { Join-Path $binaryDir 'core' }
    New-Item -ItemType Directory -Force -Path $coreOut | Out-Null
    $coreFiles | Where-Object { $trustedFiles.Contains($_.Name) } | Copy-Item -Destination $coreOut -Force
    $source = @{source=$expectedUrl;sha256=$expectedHash;version=$CoreVersion}
    [IO.File]::WriteAllText((Join-Path $coreOut 'SOURCE.json'), ($source | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
    if ($osName -ne 'windows' -and $env:OS -ne 'Windows_NT') {
        & chmod +x (Join-Path $package $relativeExe) (Join-Path $coreOut $coreExe)
        if ($LASTEXITCODE -ne 0) { throw 'Executable permission setup failed.' }
    }
    if ($osName -eq 'macos') {
        # --deep would re-sign the official core and invalidate the embedded official digests.
        & codesign --force --sign - (Join-Path $package 'MinTunClient.app')
        if ($LASTEXITCODE -ne 0) { throw 'Ad-hoc macOS signing failed.' }
    }
    foreach ($entry in $trustedFiles.GetEnumerator()) {
        if ((Get-FileHash -LiteralPath (Join-Path $coreOut $entry.Key) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry.Value) {
            throw 'Packaged core was changed after generating the embedded trust manifest.'
        }
    }
    $publications = @(@{ Source = $package; Destination = $finalPackage })
    if ($Configuration -eq 'Release') {
        $manifest = @{ product='MinTun Client';version=$version;os=$osName;arch=$arch;executable=$relativeExe;sha256=(Get-FileHash (Join-Path $package $relativeExe) -Algorithm SHA256).Hash.ToLowerInvariant() }
        [IO.File]::WriteAllText((Join-Path $package 'mintun-release.json'), ($manifest | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
        if ($osName -eq 'linux') {
            @"
[Desktop Entry]
Type=Application
Name=MinTun
Comment=Private VPN client
Exec=MinTunClient
Icon=mintun
Terminal=false
Categories=Network;
"@ | Set-Content (Join-Path $package 'mintun.desktop') -Encoding UTF8
            Copy-Item (Join-Path $root 'assets\mintun.png') $package -Force
        }
        $name = if ($osName -eq 'windows') { 'MinTunClient-win-x64.zip' } else { "MinTunClient-$osName-$arch.tar.gz" }
        $packageArchive = Join-Path $staging $name
        if ($extension -eq 'zip') {
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            Add-Type -AssemblyName System.IO.Compression
            $members = @(Get-ChildItem -LiteralPath $package -Recurse -Force)
            foreach ($member in $members) {
                if (($member.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Package members may not be links or reparse points.' }
            }
            $prefix = [IO.Path]::GetFullPath($package) + [IO.Path]::DirectorySeparatorChar
            $archive = [IO.Compression.ZipFile]::Open($packageArchive, [IO.Compression.ZipArchiveMode]::Create)
            try {
                foreach ($member in $members) {
                    if ($member.PSIsContainer) { continue }
                    $entryName = $member.FullName.Substring($prefix.Length).Replace('\', '/')
                    [IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                        $archive, $member.FullName, $entryName, [IO.Compression.CompressionLevel]::Optimal
                    ) | Out-Null
                }
            } finally { $archive.Dispose() }
            Copy-Item (Join-Path $package 'MinTunClient.exe') (Join-Path $staging 'MinTunClient.exe')
        } else {
            $go = if (Test-Path (Join-Path $tools 'go\bin\go.exe')) { Join-Path $tools 'go\bin\go.exe' } else { (Get-Command go -ErrorAction Stop).Source }
            & $go run (Join-Path $PSScriptRoot 'package-tar.go') $package $packageArchive
            if ($LASTEXITCODE -ne 0) { throw 'Application archive creation failed.' }
        }
        $publications += @{ Source = $packageArchive; Destination = (Join-Path $output $name) }
        if ($osName -eq 'windows') {
            $publications += @{ Source = (Join-Path $staging 'MinTunClient.exe'); Destination = (Join-Path $output 'MinTunClient.exe') }
        }
    }
    foreach ($item in $publications) {
        $previous = $null
        if (Test-Path -LiteralPath $item.Destination) {
            $previous = "$($item.Destination).previous-$([Guid]::NewGuid().ToString('N'))"
            Move-Item -LiteralPath $item.Destination -Destination $previous
        }
        try { Move-Item -LiteralPath $item.Source -Destination $item.Destination }
        catch {
            if ($previous -and -not (Test-Path -LiteralPath $item.Destination)) {
                Move-Item -LiteralPath $previous -Destination $item.Destination
            }
            throw
        }
    }
    if ($Configuration -eq 'Release') {
        $packageArchive = Join-Path $output $name
        Get-Item $packageArchive | Select-Object Name,Length,FullName
        Get-FileHash $packageArchive -Algorithm SHA256
    } else {
        Get-Item (Join-Path $finalPackage $relativeExe) | Select-Object Name,Length,FullName
    }
} finally {
    Pop-Location
    [Environment]::SetEnvironmentVariable('MINTUN_TRUSTED_CORE_MANIFEST', $previousTrustManifest, 'Process')
    [Environment]::SetEnvironmentVariable('RUST_FONTCONFIG_DLOPEN', $previousFontconfigDlopen, 'Process')
    foreach ($name in $previousCrossEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $previousCrossEnvironment[$name], 'Process')
    }
    if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force }
}
