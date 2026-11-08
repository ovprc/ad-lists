[CmdletBinding()]
param(
    [string]$AndroidSdk = '',
    [string]$JavaHome = '',
    [string]$Go = ''
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Split-Path $PSScriptRoot -Parent
$tools = Join-Path $root '.tools'
if (-not $AndroidSdk) { $AndroidSdk = Join-Path $tools 'android-sdk' }
if (-not $JavaHome) { $JavaHome = Join-Path $tools 'jdk-17.0.21+9' }
if (-not $Go) { $Go = Join-Path $tools 'go\bin\go.exe' }
$tag = 'v1.15.0-alpha.13'
$sourceHash = '29047987ed69ba790f2ae4eec62abf41bd1619d093af071f505b4ba081e06b44'
$archive = Join-Path $tools "sing-box-$tag.tar.gz"
$ndk = Join-Path $AndroidSdk 'ndk\28.0.13004108'
foreach ($required in @($Go, (Join-Path $JavaHome 'bin\javac.exe'), (Join-Path $ndk 'source.properties'), (Join-Path $AndroidSdk 'platforms\android-35\android.jar'))) {
    if (!(Test-Path -LiteralPath $required -PathType Leaf)) { throw "Missing Android build prerequisite: $required" }
}
if (!(Test-Path -LiteralPath $archive)) {
    Invoke-WebRequest -UseBasicParsing -Uri "https://codeload.github.com/SagerNet/sing-box/tar.gz/refs/tags/$tag" -OutFile $archive
}
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $sourceHash) { throw 'Pinned sing-box source archive SHA256 mismatch' }
$env:JAVA_HOME = $JavaHome
$env:ANDROID_HOME = $AndroidSdk
$env:ANDROID_SDK_ROOT = $AndroidSdk
$env:ANDROID_NDK_HOME = $ndk
$env:ANDROID_NDK_ROOT = $ndk
$env:GOBIN = Join-Path $tools 'gomobile-bin'
$env:GOPATH = Join-Path $tools 'go-work'
$env:GOMODCACHE = Join-Path $tools 'go-modcache'
$env:GOCACHE = Join-Path $tools 'go-buildcache'
$env:GOTELEMETRY = 'off'
$tar = Join-Path $env:SystemRoot 'System32\tar.exe'
$env:PATH = "$env:GOBIN;$(Split-Path $Go -Parent);$(Join-Path $JavaHome 'bin');$(Join-Path $root '.tools\w64devkit\bin');$env:PATH"
New-Item -ItemType Directory -Force $env:GOBIN | Out-Null
function Run([string]$Program, [string[]]$Arguments) {
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Program exited with code $LASTEXITCODE" }
}
Run $Go @('install', 'github.com/sagernet/gomobile/cmd/gomobile@v0.1.12')
Run $Go @('install', 'github.com/sagernet/gomobile/cmd/gobind@v0.1.12')
# Use a pristine extraction, never trust or modify a developer's cached source tree.
$buildSource = Join-Path $tools ('libbox-build-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $buildSource | Out-Null
$libs = Join-Path $root 'android\app\libs'
$output = Join-Path $root 'artifacts\android'
New-Item -ItemType Directory -Force $libs, $output | Out-Null
$tags = 'with_quic,with_wireguard,with_utls,with_clash_api,badlinkname,tfogo_checklinkname0'
try {
    Run $tar @('-xzf', $archive, '--strip-components=1', '-C', $buildSource)
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'android-libbox\mintun.go') -Destination (Join-Path $buildSource 'experimental\libbox\mintun.go')
    Push-Location $buildSource
    try {
        # Equivalent to upstream cmd/internal/build_libbox's Android bind, without its
        # second legacy AAR, naive/cronet, tailscale, usbip, OpenVPN or OpenConnect extras.
        # VLESS/VMess, REALITY/uTLS, multiplexing, QUIC and WireGuard remain real upstream implementations.
        $flags = '-s -w -buildid= -checklinkname=0 -X github.com/sagernet/sing-box/constant.Version=1.15.0-alpha.13 -extldflags=-Wl,-z,max-page-size=16384'
        Run (Join-Path $env:GOBIN 'gomobile.exe') @('bind', '-v', '-o', (Join-Path $libs 'libbox.aar'),
            '-target=android/arm64,android/amd64', '-androidapi=26', '-javapkg=io.nekohasekai', '-libname=box',
            '-trimpath', '-buildvcs=false', '-tags', $tags, '-ldflags', $flags, './experimental/libbox')
    } finally { Pop-Location }
    Run $tar @('-czf', (Join-Path $output 'libbox-1.15.0-alpha.13-mintun-source.tar.gz'), '-C', $buildSource, '.')
    $provenance = [ordered]@{
        tag = $tag; commit = '824dbcfb4dd0a95921840b1737b950cde590241e'; sourceArchiveSha256 = $sourceHash
        gomobile = 'github.com/sagernet/gomobile@v0.1.12'; tags = $tags; ndk = '28.0.13004108'; androidApi = 26
        go = (& $Go version | Out-String).Trim(); extensionSha256 = (Get-FileHash (Join-Path $PSScriptRoot 'android-libbox\mintun.go')).Hash.ToLowerInvariant()
        aarSha256 = (Get-FileHash (Join-Path $libs 'libbox.aar')).Hash.ToLowerInvariant()
    }
    $json = $provenance | ConvertTo-Json
    [IO.File]::WriteAllText((Join-Path $output 'libbox-build.json'), $json, [Text.UTF8Encoding]::new($false))
    Copy-Item -LiteralPath (Join-Path $output 'libbox-build.json') -Destination (Join-Path $root 'android\app\src\main\assets\libbox-build.json')
    Write-Output "Source-built libbox: $(Join-Path $libs 'libbox.aar')"
    Write-Output 'No APK was installed and no VPN service was started.'
} finally {
    # This unique directory is created solely by this invocation; caches/source archives remain intact.
    if (Test-Path -LiteralPath $buildSource) { Remove-Item -LiteralPath $buildSource -Recurse -Force }
}
