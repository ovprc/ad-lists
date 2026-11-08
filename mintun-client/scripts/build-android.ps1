[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Debug',
    [switch]$BuildLibbox,
    [switch]$LibboxOnly,
    [switch]$SkipRust,
    [string]$AndroidSdk = '',
    [string]$JavaHome = ''
)
# Builds only. This script never invokes adb, installs an APK, starts a VPN or alters SDK licenses.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Split-Path $PSScriptRoot -Parent
$tools = Join-Path $root '.tools'
if (-not $AndroidSdk) { $AndroidSdk = Join-Path $tools 'android-sdk' }
if (-not $JavaHome) { $JavaHome = Join-Path $tools 'jdk-17.0.21+9' }
$env:JAVA_HOME = $JavaHome
$env:ANDROID_HOME = $AndroidSdk
$env:ANDROID_SDK_ROOT = $AndroidSdk
$env:ANDROID_PLATFORM = 'android-35'
$env:ANDROID_JAR = Join-Path $AndroidSdk 'platforms/android-35/android.jar'
$env:ANDROID_BUILD_TOOLS_VERSION = '35.0.0'
$env:ANDROID_D8_JAR = Join-Path $AndroidSdk 'build-tools/35.0.0/lib/d8.jar'
$env:ANDROID_NDK_HOME = Join-Path $AndroidSdk 'ndk\28.0.13004108'
$env:ANDROID_NDK_ROOT = $env:ANDROID_NDK_HOME
$env:PATH = "$(Join-Path $JavaHome 'bin');$(Join-Path $root '.tools\cargo\bin');$(Join-Path $root '.tools\w64devkit\bin');$env:PATH"
$env:CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUSTFLAGS = '-C link-self-contained=yes'
foreach ($required in @((Join-Path $JavaHome 'bin\javac.exe'), (Join-Path $env:ANDROID_NDK_HOME 'source.properties'), (Join-Path $AndroidSdk 'platforms\android-35\android.jar'), (Join-Path $AndroidSdk 'build-tools\35.0.0\aapt2.exe'), (Join-Path $AndroidSdk 'build-tools\35.0.0\apksigner.bat'), (Join-Path $AndroidSdk 'build-tools\35.0.0\zipalign.exe'))) {
    if (!(Test-Path -LiteralPath $required -PathType Leaf)) { throw "Missing Android build prerequisite: $required" }
}
if ($BuildLibbox -or $LibboxOnly) {
    & (Join-Path $PSScriptRoot 'build-android-libbox.ps1') -AndroidSdk $AndroidSdk -JavaHome $JavaHome
    if (!$?) { throw 'Source-built libbox failed' }
}
if ($LibboxOnly) { return }
if (!(Test-Path (Join-Path $root 'android\app\libs\libbox.aar'))) {
    throw 'Missing source-built libbox. Run scripts/build-android.ps1 -BuildLibbox.'
}
if ($Configuration -eq 'Release' -and $SkipRust) {
    throw 'Release builds must compile both optimized Rust ABIs; -SkipRust is only supported for Debug.'
}
if (!$SkipRust) {
    $cargoNdk = Join-Path $tools 'cargo\bin\cargo-ndk.exe'
    if (!(Test-Path -LiteralPath $cargoNdk -PathType Leaf)) {
        & (Join-Path $PSScriptRoot 'cargo.ps1') install cargo-ndk --version 4.1.2 --locked
        if (!$?) { throw 'Could not provision cargo-ndk 4.1.2' }
    }
    $installedNdk = @(& (Join-Path $PSScriptRoot 'cargo.ps1') ndk --version)
    if ($LASTEXITCODE -ne 0 -or ($installedNdk -join ' ') -notmatch '^cargo-ndk 4\.1\.2(?:\s|$)') {
        throw 'Existing cargo-ndk is not 4.1.2; reconcile the local tool explicitly rather than replacing it during a build.'
    }
    $arguments = @('ndk', '-t', 'arm64-v8a', '-t', 'x86_64', '--platform', '26', '-o', (Join-Path $root 'android\app\src\main\jniLibs'), 'build', '--lib', '--locked')
    if ($Configuration -eq 'Release') { $arguments += '--release' }
    & (Join-Path $PSScriptRoot 'cargo.ps1') @arguments
    if (!$?) { throw 'Android Rust build failed' }
}
$gradleVersion = '8.11.1'
$gradleHash = 'f397b287023acdba1e9f6fc5ea72d22dd63669d59ed4a289a29b1a76eee151c6'
$gradleArchive = Join-Path $tools "gradle-$gradleVersion-bin.zip"
$gradle = Join-Path $tools "gradle-$gradleVersion\bin\gradle.bat"
if (!(Test-Path -LiteralPath $gradle)) {
    if (!(Test-Path -LiteralPath $gradleArchive)) {
        Invoke-WebRequest -UseBasicParsing -Uri "https://services.gradle.org/distributions/gradle-$gradleVersion-bin.zip" -OutFile $gradleArchive
    }
    if ((Get-FileHash -LiteralPath $gradleArchive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $gradleHash) { throw 'Gradle distribution SHA256 mismatch' }
    Expand-Archive -LiteralPath $gradleArchive -DestinationPath $tools -Force
}
$env:GRADLE_USER_HOME = Join-Path $tools 'gradle-home'
$signing = $null
try {
    if ($Configuration -eq 'Release') {
        $signing = & (Join-Path $PSScriptRoot 'android-signing.ps1') -JavaHome $JavaHome
        Write-Output "Permanent Android certificate SHA256 $($signing.CertificateSha256)"
        Write-Output "Private signing recovery: $($signing.RecoveryFile)"
        Write-Output "Private sibling signing backup: $($signing.BackupDirectory)"
    }
    Push-Location (Join-Path $root 'android')
    try {
        & $gradle --no-daemon --console=plain (':app:assemble' + $Configuration)
        if ($LASTEXITCODE -ne 0) { throw "Gradle Android build exited with $LASTEXITCODE" }
    } finally { Pop-Location }
    $output = Join-Path $root 'artifacts\android'
    New-Item -ItemType Directory -Force $output | Out-Null
    $variant = $Configuration.ToLowerInvariant()
    $apksigner = Join-Path $AndroidSdk 'build-tools\35.0.0\apksigner.bat'
    $zipalign = Join-Path $AndroidSdk 'build-tools\35.0.0\zipalign.exe'
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $verified = @()
    $certificateFingerprint = $null
    foreach ($item in @(@('arm64-v8a', 'arm64'), @('x86_64', 'x64'))) {
        $apk = Join-Path $root "android\app\build\outputs\apk\$variant\app-$($item[0])-$variant.apk"
        if (!(Test-Path -LiteralPath $apk -PathType Leaf)) { throw "Expected APK is missing: $apk" }
        & $zipalign -c -P 16 -v 4 $apk
        if ($LASTEXITCODE -ne 0) { throw "APK alignment verification failed for $($item[0])" }
        $verification = @(& $apksigner verify --verbose --print-certs $apk)
        if ($LASTEXITCODE -ne 0) { throw "APK signature verification failed for $($item[0])" }
        $verification | Write-Output
        $certificates = [regex]::Matches(($verification -join "`n"), '(?m)^Signer #1 certificate SHA-256 digest:\s*([a-fA-F0-9]{64})\s*$')
        if ($certificates.Count -ne 1 -or ($verification -join "`n") -match '(?m)^Signer #(?:[2-9]|[1-9][0-9]+) certificate SHA-256 digest:') {
            throw 'Expected exactly one APK signing certificate.'
        }
        $fingerprint = $certificates[0].Groups[1].Value.ToLowerInvariant()
        if ($null -ne $certificateFingerprint -and $certificateFingerprint -cne $fingerprint) { throw 'APK ABI signing certificates differ.' }
        $certificateFingerprint = $fingerprint
        if ($Configuration -eq 'Release' -and $fingerprint -cne $signing.CertificateSha256) { throw 'Release APK does not use the permanent local signing certificate.' }
        $archive = [IO.Compression.ZipFile]::OpenRead($apk)
        try {
            foreach ($entry in $archive.Entries) {
                if ($entry.FullName -match '(?i)(?:^|/)(?:\.private|android-signing)(?:/|$)|(?:^|/)(?:credentials\.dpapi|recovery\.json|signing\.lock|mintun-release[^/]*|[^/]*\.(?:p12|pfx|jks|keystore))$') {
                    throw 'An APK contains a prohibited signing/private file.'
                }
            }
        } finally { $archive.Dispose() }
        $verified += [pscustomobject]@{ Source = $apk; Destination = (Join-Path $output "MinTunClient-android-$($item[1]).apk") }
    }
    # Both APKs must pass all checks before either is copied to the release output.
    foreach ($item in $verified) {
        $stagedApk = "$($item.Destination).staged-$([Guid]::NewGuid().ToString('N'))"
        $stagedChecksum = "$stagedApk.sha256"
        try {
            Copy-Item -LiteralPath $item.Source -Destination $stagedApk
            $hash = (Get-FileHash -LiteralPath $stagedApk -Algorithm SHA256).Hash.ToLowerInvariant()
            [IO.File]::WriteAllText($stagedChecksum, ($hash + '  ' + [IO.Path]::GetFileName($item.Destination) + "`n"), [Text.UTF8Encoding]::new($false))
            foreach ($file in @(
                @{ Source = $stagedApk; Destination = $item.Destination },
                @{ Source = $stagedChecksum; Destination = ($item.Destination + '.sha256') }
            )) {
                $previous = $null
                if (Test-Path -LiteralPath $file.Destination) {
                    $previous = "$($file.Destination).previous-$([Guid]::NewGuid().ToString('N'))"
                    Move-Item -LiteralPath $file.Destination -Destination $previous
                }
                try { Move-Item -LiteralPath $file.Source -Destination $file.Destination }
                catch {
                    if ($previous -and -not (Test-Path -LiteralPath $file.Destination)) {
                        Move-Item -LiteralPath $previous -Destination $file.Destination
                    }
                    throw
                }
            }
            Write-Output "$($item.Destination) SHA256 $hash"
        } finally {
            foreach ($file in @($stagedApk, $stagedChecksum)) {
                if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file -Force }
            }
        }
    }
} finally {
    if ($Configuration -eq 'Release') {
        foreach ($name in @('MINTUN_ANDROID_KEYSTORE', 'MINTUN_ANDROID_KEY_ALIAS', 'MINTUN_ANDROID_STORE_PASSWORD', 'MINTUN_ANDROID_KEY_PASSWORD', 'MINTUN_ANDROID_CERT_SHA256')) {
            [Environment]::SetEnvironmentVariable($name, $null, 'Process')
        }
    }
}
Write-Output 'APK builds complete. Nothing was installed; no tunnel was started.'
