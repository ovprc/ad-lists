<#
.SYNOPSIS
Loads the permanent local Android identity, creating it only on the first authorized use.
.DESCRIPTION
Windows only. Default LoadOrCreate never replaces an existing keystore. Use -Mode Load
for routine retrieval without creation; -Mode Recover -RecoveryFile <private recovery.json>
explicitly restores DPAPI credentials for the SAME keystore after a user/machine change.
MINTUN_ANDROID_KEYSTORE and MINTUN_ANDROID_KEY_ALIAS contain public configuration.
MINTUN_ANDROID_STORE_PASSWORD and MINTUN_ANDROID_KEY_PASSWORD are process-only secrets;
keytool receives their NAMES through -storepass:env/-keypass:env, never their values in argv.
Gradle reads those same four environment variables. Do not enable shell tracing, Gradle
--debug, environment dumps, or publish .private or the sibling signing backup.
Routine credentials use DPAPI CurrentUser, not portable encryption. recovery.json contains
the plaintext password and fingerprint and IS portable: keep it with mintun-release.p12
in the separately ACL-protected sibling backup, and store an additional offline copy safely.
Only safe paths, alias and certificate SHA256 are returned; no credentials are printed.
#>
[CmdletBinding()]
param(
    [ValidateSet('LoadOrCreate', 'Load', 'Recover')][string]$Mode = 'LoadOrCreate',
    [string]$RecoveryFile = '',
    [string]$JavaHome = ''
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Split-Path $PSScriptRoot -Parent
$directory = Join-Path $root '.private\android-signing'
$keystore = Join-Path $directory 'mintun-release.p12'
$credentialsPath = Join-Path $directory 'credentials.dpapi'
$recoveryPath = Join-Path $directory 'recovery.json'
$stagedKey = Join-Path $directory 'mintun-release.pending.p12'
$alias = 'mintun-release'
$phase = 'checking Windows signing prerequisites'
$lock = $null
$password = $null
$credentialBytes = $null
$plainBytes = $null

function Assert-NoReparsePoint([string]$Path) {
    $current = [IO.Path]::GetFullPath($Path)
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            if (([IO.File]::GetAttributes($current) -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'Signing paths must not contain reparse points.'
            }
        }
        $parent = [IO.Path]::GetDirectoryName($current)
        if ($parent -eq $current) { break }
        $current = $parent
    }
}

function New-PrivateDirectoryAcl {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($script:ownerSid)
    foreach ($sid in $script:allowedSids) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
    }
    return $acl
}

function Protect-Directory([string]$Path) {
    Assert-NoReparsePoint $Path
    $acl = New-PrivateDirectoryAcl
    if (Test-Path -LiteralPath $Path) {
        if (!(Test-Path -LiteralPath $Path -PathType Container)) { throw 'Signing directory is not a directory.' }
        if ([IO.Directory].GetMethod('SetAccessControl', [type[]]@([string], [Security.AccessControl.DirectorySecurity]))) {
            [IO.Directory]::SetAccessControl($Path, $acl)
        } else {
            [IO.FileSystemAclExtensions]::SetAccessControl([IO.DirectoryInfo]::new($Path), $acl)
        }
    } else {
        # Apply the DACL as part of creation, not after an inherited-permission window.
        $info = [IO.DirectoryInfo]::new($Path)
        if ($info.GetType().GetMethod('Create', [type[]]@([Security.AccessControl.DirectorySecurity]))) {
            $info.Create($acl)
        } else {
            [IO.FileSystemAclExtensions]::Create($info, $acl)
        }
    }
}

function Protect-File([string]$Path) {
    Assert-NoReparsePoint $Path
    $acl = [Security.AccessControl.FileSecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($script:ownerSid)
    foreach ($sid in $script:allowedSids) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'Allow'))
    }
    if ([IO.File].GetMethod('SetAccessControl', [type[]]@([string], [Security.AccessControl.FileSecurity]))) {
        [IO.File]::SetAccessControl($Path, $acl)
    } else {
        [IO.FileSystemAclExtensions]::SetAccessControl([IO.FileInfo]::new($Path), $acl)
    }
}

function Write-PrivateFile([string]$Path, [byte[]]$Bytes) {
    Assert-NoReparsePoint $Path
    $temporary = $Path + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    # The private parent supplies the restrictive ACL even before the explicit file DACL.
    $stream = [IO.FileStream]::new($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush($true)
    } finally { $stream.Dispose() }
    Protect-File $temporary
    if (Test-Path -LiteralPath $Path) {
        $previous = $temporary + '.previous'
        [IO.File]::Replace($temporary, $Path, $previous)
        [IO.File]::Delete($previous)
    } else {
        [IO.File]::Move($temporary, $Path)
    }
}

function Invoke-PrivateKeytool([string[]]$Arguments) {
    # JDK tools write successful status messages to stderr. Capture them without
    # PowerShell 5.1 turning NativeCommandError into a terminating/logged exception.
    $ErrorActionPreference = 'Continue'
    $result = @(& $script:keytool @Arguments 2>&1)
    $exitCode = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    if ($exitCode -ne 0) { throw 'Keytool failed; its output is intentionally not logged.' }
    return $result
}

function New-SiblingBackupPath {
    $name = [IO.Path]::GetFileName($script:root) + '-android-signing-backup-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N')
    return (Join-Path (Split-Path $script:root -Parent) $name)
}

function Get-SigningFingerprint([string]$Path) {
    # certreq exercises the private key/password too, rather than only reading the certificate.
    $request = @(Invoke-PrivateKeytool -Arguments @('-certreq', '-alias', $script:alias, '-keystore', $Path, '-storetype', 'PKCS12', '-storepass:env', 'MINTUN_ANDROID_STORE_PASSWORD', '-keypass:env', 'MINTUN_ANDROID_KEY_PASSWORD'))
    $request = $null
    $certificate = @(Invoke-PrivateKeytool -Arguments @('-exportcert', '-rfc', '-alias', $script:alias, '-keystore', $Path, '-storetype', 'PKCS12', '-storepass:env', 'MINTUN_ANDROID_STORE_PASSWORD'))
    $pem = $certificate -join "`n"
    $match = [regex]::Match($pem, '(?s)-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----')
    if (!$match.Success) { throw 'Signing certificate output is invalid.' }
    $der = [Convert]::FromBase64String(($match.Groups[1].Value -replace '\s', ''))
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($der))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

try {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Local signing credentials require Windows DPAPI CurrentUser.' }
    Add-Type -AssemblyName System.Security
    $ownerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $allowedSids = @($ownerSid, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'), [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    if (!$JavaHome) { $JavaHome = Join-Path $root '.tools\jdk-17.0.21+9' }
    $keytool = Join-Path $JavaHome 'bin\keytool.exe'
    if (!(Test-Path -LiteralPath $keytool -PathType Leaf)) { throw 'JDK 17 keytool is missing.' }
    $env:JAVA_HOME = $JavaHome
    $phase = 'protecting the private signing directory (current user, SYSTEM, Administrators only)'
    Protect-Directory (Join-Path $root '.private')
    Protect-Directory $directory
    foreach ($path in @($keystore, $credentialsPath, $recoveryPath, $stagedKey)) {
        if (Test-Path -LiteralPath $path) { Protect-File $path }
    }
    $lockPath = Join-Path $directory 'signing.lock'
    Assert-NoReparsePoint $lockPath
    if (Test-Path -LiteralPath $lockPath) { Protect-File $lockPath }
    $lock = [IO.FileStream]::new($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    $hasKey = Test-Path -LiteralPath $keystore -PathType Leaf
    $recoveringStage = Test-Path -LiteralPath $stagedKey -PathType Leaf
    if ($recoveringStage -and ($hasKey -or $Mode -ne 'Recover')) {
        $phase = "recovering an interrupted first creation: preserve $stagedKey and use -Mode Recover -RecoveryFile $recoveryPath; do not generate another identity"
        throw 'Staged signing identity needs explicit recovery.'
    }
    $keyToRead = if ($recoveringStage) { $stagedKey } else { $keystore }
    $hasKey = $hasKey -or $recoveringStage
    if (!$hasKey -and ($Mode -ne 'LoadOrCreate' -or (Test-Path -LiteralPath $credentialsPath) -or (Test-Path -LiteralPath $recoveryPath))) {
        $phase = "recovering the missing permanent keystore from the private sibling backup into $keystore; no replacement key was generated"
        throw 'The permanent keystore is missing.'
    }
    if ($hasKey) {
        $phase = "loading credentials for the existing key; if missing/unreadable use -Mode Recover -RecoveryFile <private recovery.json>; NEVER delete or regenerate $keystore"
        if ($Mode -eq 'Recover') {
            if (!$RecoveryFile -or !(Test-Path -LiteralPath $RecoveryFile -PathType Leaf)) { throw 'Explicit portable recovery file is required.' }
            Protect-File $RecoveryFile
            $identity = [IO.File]::ReadAllText($RecoveryFile) | ConvertFrom-Json
        } else {
            if (!(Test-Path -LiteralPath $credentialsPath -PathType Leaf)) { throw 'Routine credentials are missing; explicit recovery is required.' }
            $credentialBytes = [IO.File]::ReadAllBytes($credentialsPath)
            $plainBytes = [Security.Cryptography.ProtectedData]::Unprotect($credentialBytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
            $identity = [Text.Encoding]::UTF8.GetString($plainBytes) | ConvertFrom-Json
        }
        if ($identity.format -ne 1 -or $identity.alias -cne $alias -or ($identity.fingerprint -cnotmatch '^[a-f0-9]{64}$' -and !($recoveringStage -and $identity.fingerprint -eq '')) -or [string]::IsNullOrWhiteSpace($identity.password) -or [string]::IsNullOrWhiteSpace($identity.backupDirectory)) {
            throw 'Signing credentials have an unexpected identity or format.'
        }
        $password = [string]$identity.password
        $env:MINTUN_ANDROID_STORE_PASSWORD = $password
        $env:MINTUN_ANDROID_KEY_PASSWORD = $password
        $actual = Get-SigningFingerprint $keyToRead
        if ($recoveringStage -and $identity.fingerprint -eq '') { $identity.fingerprint = $actual }
        if ($actual -cne $identity.fingerprint) { throw 'Existing keystore fingerprint differs from its saved identity.' }
        if ($Mode -eq 'Recover') {
            # A portable recovery may be used under a new Windows account/project path.
            # Retain the key/password/fingerprint, but create a fresh private sibling backup.
            $identity.backupDirectory = New-SiblingBackupPath
            $plainBytes = [Text.Encoding]::UTF8.GetBytes(($identity | ConvertTo-Json -Compress))
            $credentialBytes = [Security.Cryptography.ProtectedData]::Protect($plainBytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
            Write-PrivateFile $credentialsPath $credentialBytes
            Write-PrivateFile $recoveryPath $plainBytes
            if ($recoveringStage) {
                [IO.File]::Move($stagedKey, $keystore)
                Protect-File $keystore
            }
            Protect-Directory $identity.backupDirectory
            foreach ($name in @('mintun-release.p12', 'credentials.dpapi', 'recovery.json')) {
                Write-PrivateFile (Join-Path $identity.backupDirectory $name) ([IO.File]::ReadAllBytes((Join-Path $directory $name)))
            }
        }
    } else {
        $phase = 'creating the first permanent identity and private portable recovery; interrupted files must be preserved for recovery'
        $random = New-Object byte[] 48
        $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($random); $password = [Convert]::ToBase64String($random) }
        finally { $rng.Dispose(); [Array]::Clear($random, 0, $random.Length) }
        $env:MINTUN_ANDROID_STORE_PASSWORD = $password
        $env:MINTUN_ANDROID_KEY_PASSWORD = $password
        # Persist the password before keytool can create any key bytes. If creation is
        # interrupted, preserve this recovery file and the staged key for explicit recovery.
        $backup = New-SiblingBackupPath
        $identity = [pscustomobject]@{ format = 1; alias = $alias; password = $password; fingerprint = ''; keystoreFile = 'mintun-release.p12'; backupDirectory = $backup }
        $plainBytes = [Text.Encoding]::UTF8.GetBytes(($identity | ConvertTo-Json -Compress))
        $credentialBytes = [Security.Cryptography.ProtectedData]::Protect($plainBytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
        Write-PrivateFile $credentialsPath $credentialBytes
        Write-PrivateFile $recoveryPath $plainBytes
        $generation = @(Invoke-PrivateKeytool -Arguments @('-genkeypair', '-noprompt', '-alias', $alias, '-keystore', $stagedKey, '-storetype', 'PKCS12', '-keyalg', 'RSA', '-keysize', '3072', '-sigalg', 'SHA256withRSA', '-validity', '10000', '-dname', 'CN=MinTun Client', '-storepass:env', 'MINTUN_ANDROID_STORE_PASSWORD', '-keypass:env', 'MINTUN_ANDROID_KEY_PASSWORD'))
        $generation = $null
        Protect-File $stagedKey
        $actual = Get-SigningFingerprint $stagedKey
        $identity.fingerprint = $actual
        $plainBytes = [Text.Encoding]::UTF8.GetBytes(($identity | ConvertTo-Json -Compress))
        $credentialBytes = [Security.Cryptography.ProtectedData]::Protect($plainBytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
        Write-PrivateFile $credentialsPath $credentialBytes
        Write-PrivateFile $recoveryPath $plainBytes
        # No overwrite: the permanent identity is published only after recovery credentials exist.
        [IO.File]::Move($stagedKey, $keystore)
        Protect-Directory $backup
        foreach ($name in @('mintun-release.p12', 'credentials.dpapi', 'recovery.json')) {
            Write-PrivateFile (Join-Path $backup $name) ([IO.File]::ReadAllBytes((Join-Path $directory $name)))
        }
    }
    $phase = 'checking the private portable recovery and sibling backup; use explicit -Mode Recover if recovery/backup files are missing, never regenerate the key'
    if (!(Test-Path -LiteralPath $recoveryPath -PathType Leaf)) { throw 'Portable recovery file is missing.' }
    $portable = [IO.File]::ReadAllText($recoveryPath) | ConvertFrom-Json
    if ($portable.alias -cne $alias -or $portable.fingerprint -cne $actual -or $portable.password -cne $password) { throw 'Portable recovery does not match the permanent identity.' }
    $portable = $null
    $backup = [IO.Path]::GetFullPath([string]$identity.backupDirectory)
    if ([IO.Path]::GetDirectoryName($backup) -ine (Split-Path $root -Parent) -or !([IO.Path]::GetFileName($backup).StartsWith(([IO.Path]::GetFileName($root) + '-android-signing-backup-'), [StringComparison]::Ordinal))) {
        throw 'Signing backup must be a distinct sibling directory of this project.'
    }
    if (!(Test-Path -LiteralPath $backup -PathType Container)) { throw 'Private signing backup is missing.' }
    Protect-Directory $backup
    foreach ($name in @('mintun-release.p12', 'credentials.dpapi', 'recovery.json')) {
        $backupFile = Join-Path $backup $name
        if (!(Test-Path -LiteralPath $backupFile -PathType Leaf)) { throw 'Private signing backup is incomplete.' }
        Protect-File $backupFile
    }
    if ((Get-FileHash -LiteralPath (Join-Path $backup 'mintun-release.p12') -Algorithm SHA256).Hash -cne (Get-FileHash -LiteralPath $keystore -Algorithm SHA256).Hash) {
        throw 'The sibling backup contains a different keystore.'
    }
    $portable = [IO.File]::ReadAllText((Join-Path $backup 'recovery.json')) | ConvertFrom-Json
    if ($portable.alias -cne $alias -or $portable.fingerprint -cne $actual -or $portable.password -cne $password) { throw 'Backup recovery does not match the permanent identity.' }
    $portable = $null
    $env:MINTUN_ANDROID_KEYSTORE = $keystore
    $env:MINTUN_ANDROID_KEY_ALIAS = $alias
    $env:MINTUN_ANDROID_CERT_SHA256 = $actual
    [pscustomobject]@{ Keystore = $keystore; Alias = $alias; CertificateSha256 = $actual; RecoveryFile = $recoveryPath; BackupDirectory = $backup }
} catch {
    Write-Verbose ("Signing failure type {0}, HResult {1}; {2}" -f $_.Exception.GetType().FullName, $_.Exception.HResult, $_.ScriptStackTrace)
    foreach ($name in @('MINTUN_ANDROID_KEYSTORE', 'MINTUN_ANDROID_KEY_ALIAS', 'MINTUN_ANDROID_STORE_PASSWORD', 'MINTUN_ANDROID_KEY_PASSWORD', 'MINTUN_ANDROID_CERT_SHA256')) {
        [Environment]::SetEnvironmentVariable($name, $null, 'Process')
    }
    # Never interpolate exceptions/tool output: they may contain decrypted credential values.
    throw "Android signing failed while $phase. No existing permanent key was replaced."
} finally {
    if ($null -ne $lock) { $lock.Dispose() }
    if ($null -ne $plainBytes) { [Array]::Clear($plainBytes, 0, $plainBytes.Length) }
    if ($null -ne $credentialBytes) { [Array]::Clear($credentialBytes, 0, $credentialBytes.Length) }
    $password = $null
    $identity = $null
}
