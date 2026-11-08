# Creates a public source distribution only; never builds an application or publishes files.
[CmdletBinding()]
param(
    [string]$OutputDirectory = '',
    [string]$Cargo = '',
    [string]$Go = '',
    # A signed mirror may be selected, e.g. 'sum.golang.org https://sum.golang.google.cn'.
    [string]$GoSumDatabase = 'sum.golang.org',
    [ValidatePattern('^https://[a-z0-9.-]+(?:/[a-z0-9./-]*)?$')][string]$GoProxy = 'https://proxy.golang.org'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Split-Path $PSScriptRoot -Parent
$version = '2.0.2'
if (!$OutputDirectory) { $OutputDirectory = Join-Path $root "artifacts/v$version-rust" }
$output = [IO.Path]::GetFullPath($OutputDirectory)
$utf8 = [Text.UTF8Encoding]::new($false)

function Assert-NoLinks([string]$Path) {
    $current = [IO.Path]::GetFullPath($Path)
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $item.LinkType -in @('SymbolicLink', 'Junction')) {
                throw "Source paths may not traverse links/reparse points: $current"
            }
        }
        $parent = [IO.Path]::GetDirectoryName($current)
        if ($parent -eq $current) { break }
        $current = $parent
    }
}
function Get-SafeFiles([string]$Path) {
    Assert-NoLinks $Path
    foreach ($item in Get-ChildItem -LiteralPath $Path -Force) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $item.LinkType -in @('SymbolicLink', 'Junction')) {
            throw "Source inputs may not contain links/reparse points: $($item.FullName)"
        }
        if ($item.PSIsContainer) { Get-SafeFiles $item.FullName } else { $item }
    }
}
function Copy-PublicFile([string]$Relative, [string]$Destination = $Relative) {
    $source = Join-Path $root $Relative
    Assert-NoLinks $source
    if (!(Test-Path -LiteralPath $source -PathType Leaf)) { throw "Missing public source input: $Relative" }
    $target = Join-Path $payload $Destination
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target)) | Out-Null
    [IO.File]::Copy($source, $target, $false)
}
function Write-Json([string]$Path, $Value) {
    [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 12), $utf8)
}
function Run([string]$Program, [string[]]$Arguments) {
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Source packaging command failed: $Program (exit $LASTEXITCODE)" }
}
function Download([string]$Url, [string]$Destination) {
    Run $curl @('--fail', '--location', '--silent', '--show-error', '--proto', '=https', '--proto-redir', '=https',
        '--connect-timeout', '30', '--max-time', '900', '--max-filesize', '1073741824', '--output', $Destination, $Url)
}
function Hash([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Hash-Sri512([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    $algorithm = [Security.Cryptography.SHA512]::Create()
    try { 'sha512-' + [Convert]::ToBase64String($algorithm.ComputeHash($stream)) }
    finally { $algorithm.Dispose(); $stream.Dispose() }
}
function Publish-PreservingOld([string]$Source, [string]$Destination) {
    Assert-NoLinks $Destination
    $previous = $null
    if (Test-Path -LiteralPath $Destination) {
        $previous = $Destination + '.previous-' + [guid]::NewGuid().ToString('N')
        Move-Item -LiteralPath $Destination -Destination $previous
    }
    try { Move-Item -LiteralPath $Source -Destination $Destination }
    catch {
        if ($previous -and !(Test-Path -LiteralPath $Destination)) { Move-Item -LiteralPath $previous -Destination $Destination }
        throw
    }
}
function Expand-CheckedSourceTar([string]$Archive, [string]$Destination, [int]$Strip) {
    $names = @(& $tar -tf $Archive)
    if ($LASTEXITCODE -ne 0) { throw 'Unreadable source archive.' }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($name in $names) {
        $normal = $name
        while ($normal.StartsWith('./')) { $normal = $normal.Substring(2) }
        $normal = $normal.TrimEnd('/')
        if (!$normal) { continue }
        if ($normal -match '[\\:\x00-\x1f]|^/|(^|/)\.\.(/|$)' -or !$seen.Add($normal)) {
            throw 'Unsafe/duplicate member in source archive.'
        }
    }
    $types = @(& $tar -tvf $Archive)
    if ($LASTEXITCODE -ne 0 -or @($types | Where-Object { $_ -notmatch '^[-d]' }).Count) {
        throw 'Source archive contains a link, special file, or unreadable member.'
    }
    [IO.Directory]::CreateDirectory($Destination) | Out-Null
    Run $tar @('-xf', $Archive, "--strip-components=$Strip", '-C', $Destination)
    $null = @(Get-SafeFiles $Destination)
}

# Only these application inputs are public. No recursive copy from the workspace root,
# .tools, artifacts, tests, examples, exe, DIAGNOSTICS, .private, or user state is allowed.
$files = @(
    'Cargo.toml', 'Cargo.lock', 'build.rs', '.cargo/config.toml',
    'scripts/package-source.ps1', 'scripts/build-desktop.ps1', 'scripts/package-tar.go',
    'scripts/build-android.ps1', 'scripts/build-android-libbox.ps1', 'scripts/android-signing.ps1',
    'scripts/cargo.ps1', 'scripts/pkg-config-linux.cmd', 'scripts/pkg-config-linux.ps1',
    'scripts/android-libbox/mintun.go',
    'scripts/mintun-account-bridge.py', 'scripts/mintun-account-bridge.service',
    'tests/account.rs', 'tests/helper.rs', 'tests/test_account_bridge.py',
    'tests/Verify-Packaging.ps1', 'tests/fixtures/protocol-dotnet.json',
    'tests/smoke_macos_helper.py',
    'android/build.gradle', 'android/settings.gradle', 'android/gradle.properties',
    'android/app/build.gradle', 'android/app/src/main/AndroidManifest.xml',
    'android/app/src/main/assets/libbox-build.json', 'android/app/src/main/assets/libbox-provenance.json',
    'android/app/src/main/assets/licenses/GPL-3.0.txt',
    'android/app/src/main/assets/licenses/sing-box-LICENSE.txt',
    'android/app/src/main/assets/licenses/slint-NOTICE.txt'
)
$trees = [ordered]@{
    'native' = @('.rs'); 'ui' = @('.slint', '.svg'); 'assets' = @('.ico', '.icns', '.png', '.manifest')
    'android/app/src/main/java' = @('.java'); 'android/app/src/main/res' = @('.xml')
}
# Project-level legal notices may be added independently of packaging.
foreach ($name in @('LICENSE', 'LICENSE.txt', 'NOTICE', 'NOTICE.txt')) {
    if (Test-Path -LiteralPath (Join-Path $root $name) -PathType Leaf) { $files += $name }
}
Assert-NoLinks $root
Assert-NoLinks $output
[IO.Directory]::CreateDirectory($output) | Out-Null
# Keep Windows PowerShell/.NET paths short enough for vendored crate filenames.
$stage = Join-Path ([IO.Path]::GetTempPath()) ('mintun-src-' + [guid]::NewGuid().ToString('N'))
Assert-NoLinks $stage
if (Test-Path -LiteralPath $stage) { throw 'Source staging must be a fresh directory.' }
$payload = Join-Path $stage "MinTunClient-source-v$version"
[IO.Directory]::CreateDirectory($payload) | Out-Null
$oldEnvironment = @{}
foreach ($key in @('CARGO_HOME', 'RUSTUP_HOME', 'GOMODCACHE', 'GOPATH', 'GOTELEMETRY', 'GOWORK', 'GOFLAGS', 'GOPROXY', 'GOSUMDB', 'GONOSUMDB', 'GOPRIVATE', 'GOOS', 'GOARCH', 'CGO_ENABLED')) {
    $oldEnvironment[$key] = [Environment]::GetEnvironmentVariable($key, 'Process')
}
try {
    foreach ($file in $files) { Copy-PublicFile $file }
    foreach ($tree in $trees.Keys) {
        foreach ($file in Get-SafeFiles (Join-Path $root $tree)) {
            if ($file.Extension -notin $trees[$tree]) { throw "Unreviewed source-tree file type: $($file.FullName)" }
            Copy-PublicFile ($file.FullName.Substring($root.Length + 1).Replace('\', '/'))
        }
    }
    # Refuse accidental personal paths/private material in the reviewed application inputs.
    $textExtensions = @('.rs', '.toml', '.lock', '.slint', '.svg', '.ps1', '.cmd', '.go', '.gradle', '.properties', '.xml', '.json', '.txt', '.manifest', '')
    foreach ($file in Get-SafeFiles $payload) {
        if ($file.Extension -in $textExtensions) {
            $text = [IO.File]::ReadAllText($file.FullName)
            if ($text -match '(?i)[A-Z]:[\\/]+Users[\\/]|/(?:Users|home)/[^/\s]+/|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----') {
                throw "Private material/personal absolute path in public input: $($file.Name)"
            }
        }
    }
    if (!$Cargo) {
        $portableCargo = Join-Path $root '.tools/cargo/bin/cargo.exe'
        if (Test-Path -LiteralPath $portableCargo) {
            $Cargo = $portableCargo
            $env:CARGO_HOME = Join-Path $root '.tools/cargo'
            $env:RUSTUP_HOME = Join-Path $root '.tools/rustup'
        } else { $Cargo = (Get-Command cargo -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source }
    }
    if (!$Go) {
        $portableGo = Join-Path $root '.tools/go/bin/go.exe'
        if (Test-Path -LiteralPath $portableGo) { $Go = $portableGo }
        else { $Go = (Get-Command go -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source }
    }
    Assert-NoLinks $Cargo
    Assert-NoLinks $Go
    $curlName = if ($env:OS -eq 'Windows_NT') { 'curl.exe' } else { 'curl' }
    $curl = (Get-Command $curlName -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
    $tar = (Get-Command tar -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
    $thirdParty = Join-Path $payload 'third-party'
    [IO.Directory]::CreateDirectory($thirdParty) | Out-Null

    $upstream = Join-Path $thirdParty 'sing-box-v1.15.0-alpha.13.tar.gz'
    $cached = Join-Path $root '.tools/sing-box-v1.15.0-alpha.13.tar.gz'
    $upstreamHash = '29047987ed69ba790f2ae4eec62abf41bd1619d093af071f505b4ba081e06b44'
    if (Test-Path -LiteralPath $cached) { Assert-NoLinks $cached; [IO.File]::Copy($cached, $upstream) }
    else { Download 'https://codeload.github.com/SagerNet/sing-box/tar.gz/refs/tags/v1.15.0-alpha.13' $upstream }
    if ((Hash $upstream) -cne $upstreamHash) { throw 'Pinned upstream sing-box source checksum mismatch.' }
    Copy-PublicFile 'artifacts/android/libbox-1.15.0-alpha.13-mintun-source.tar.gz' 'third-party/libbox-1.15.0-alpha.13-mintun-source.tar.gz'
    Copy-PublicFile 'artifacts/android/libbox-build.json' 'third-party/libbox-build.json'
    # Prove that the reused Android archive contains exactly pristine public
    # upstream files plus the reviewed MinTun adapter, not unrelated local bytes.
    $pristineTree = Join-Path $stage 'pristine-core'
    $patchedTree = Join-Path $stage 'patched-core'
    Expand-CheckedSourceTar $upstream $pristineTree 1
    Expand-CheckedSourceTar (Join-Path $thirdParty 'libbox-1.15.0-alpha.13-mintun-source.tar.gz') $patchedTree 0
    $expected = @{}
    foreach ($file in Get-SafeFiles $pristineTree) {
        $expected[$file.FullName.Substring($pristineTree.Length + 1)] = Hash $file.FullName
    }
    $expected['experimental\libbox\mintun.go'.Replace('\', [IO.Path]::DirectorySeparatorChar)] = Hash (Join-Path $payload 'scripts/android-libbox/mintun.go')
    foreach ($file in Get-SafeFiles $patchedTree) {
        $relative = $file.FullName.Substring($patchedTree.Length + 1)
        if (!$expected.ContainsKey($relative) -or (Hash $file.FullName) -cne $expected[$relative]) {
            throw "Reused libbox source differs from the public upstream plus adapter: $relative"
        }
        $expected.Remove($relative)
    }
    if ($expected.Count) { throw 'Reused libbox archive is missing public source files.' }

    # Read the authenticated upstream manifests; never invoke module tooling in
    # the original developer source tree.
    $moduleWork = Join-Path $stage 'module-work'
    [IO.Directory]::CreateDirectory($moduleWork) | Out-Null
    foreach ($name in @('go.mod', 'go.sum')) {
        $text = @(& $tar -xOf $upstream "sing-box-1.15.0-alpha.13/$name")
        if ($LASTEXITCODE -ne 0) { throw "Could not read pinned upstream $name" }
        [IO.File]::WriteAllText((Join-Path $moduleWork $name), ($text -join "`n") + "`n", $utf8)
    }
    $lockedGoSums = @{}
    foreach ($line in [IO.File]::ReadAllLines((Join-Path $moduleWork 'go.sum'))) {
        $fields = $line.Split(' ')
        if ($fields.Length -eq 3) { $lockedGoSums[$fields[0] + '@' + $fields[1]] = $fields[2] }
    }
    $env:GOMODCACHE = Join-Path $root '.tools/go-modcache'
    $env:GOPATH = Join-Path $stage 'go-work'
    $env:GOTELEMETRY = 'off'
    $env:GOWORK = 'off'
    $env:GOFLAGS = ''
    $env:GOPROXY = $GoProxy
    if ($GoSumDatabase -notmatch '^sum\.golang\.org(?: https://[a-z0-9./-]+)?$') { throw 'Use the signed sum.golang.org database, optionally with an HTTPS mirror.' }
    $env:GOSUMDB = $GoSumDatabase
    $env:GONOSUMDB = ''
    $env:GOPRIVATE = ''
    Assert-NoLinks $env:GOMODCACHE
    $moduleInventory = [Collections.Generic.List[object]]::new()
    $moduleOutput = Join-Path $thirdParty 'go-modules'
    [IO.Directory]::CreateDirectory($moduleOutput) | Out-Null
    # Resolve package imports for the actual shipped targets/build tags, not
    # `go list -m all` (which also drags unrelated upstream test modules in).
    $windowsTags = [IO.File]::ReadAllText((Join-Path $pristineTree 'release/DEFAULT_BUILD_TAGS_WINDOWS')).Trim()
    $linuxTags = [IO.File]::ReadAllText((Join-Path $pristineTree 'release/DEFAULT_BUILD_TAGS')).Trim() + ',with_purego'
    $darwinTags = [IO.File]::ReadAllText((Join-Path $pristineTree 'release/DEFAULT_BUILD_TAGS')).Trim()
    $androidTags = ([IO.File]::ReadAllText((Join-Path $thirdParty 'libbox-build.json')) | ConvertFrom-Json).tags
    $selectedModules = [Collections.Generic.List[string]]::new()
    $selections = @(
        @($pristineTree, 'windows', 'amd64', '0', $windowsTags, './cmd/sing-box'),
        @($pristineTree, 'linux', 'amd64', '0', $linuxTags, './cmd/sing-box'),
        @($pristineTree, 'darwin', 'amd64', '1', $darwinTags, './cmd/sing-box'),
        @($pristineTree, 'darwin', 'arm64', '1', $darwinTags, './cmd/sing-box'),
        @($patchedTree, 'android', 'arm64', '1', $androidTags, './experimental/libbox'),
        @($patchedTree, 'android', 'amd64', '1', $androidTags, './experimental/libbox')
    )
    foreach ($selection in $selections) {
        $env:GOOS = $selection[1]; $env:GOARCH = $selection[2]; $env:CGO_ENABLED = $selection[3]
        Push-Location $selection[0]
        try {
            $selected = @(& $Go list -mod=readonly -deps -tags $selection[4] -f '{{if .Module}}{{if not .Module.Main}}{{.Module.Path}}@{{.Module.Version}}{{end}}{{end}}' $selection[5])
            if ($LASTEXITCODE -ne 0) { throw "Could not resolve source imports for $($selection[1])/$($selection[2])." }
            foreach ($module in $selected) { if ($module) { $selectedModules.Add($module) } }
        } finally { Pop-Location }
    }
    $modules = @($selectedModules.ToArray() | Sort-Object -Unique)
    # Gomobile is the pinned public binding generator used by the supplied script.
    $modules += 'github.com/sagernet/gomobile@v0.1.12'
    $modules = @($modules | Sort-Object -Unique)
    $env:GOOS = $oldEnvironment['GOOS']
    $env:GOARCH = $oldEnvironment['GOARCH']
    $env:CGO_ENABLED = $oldEnvironment['CGO_ENABLED']
    Push-Location $stage
    try {
        foreach ($module in $modules) {
            if (!$module) { continue }
            # These modules contain prebuilt libraries, not corresponding native
            # source. The exact native source repository is supplied separately.
            if ($module -like 'github.com/sagernet/cronet-go/lib/*') { continue }
            $download = @(& $Go mod download -json $module)
            if ($LASTEXITCODE -ne 0) { throw ("Pinned Go module download failed: $module`n" + ($download -join "`n")) }
            $info = ($download -join "`n") | ConvertFrom-Json
            if ($info.PSObject.Properties['Error']) { throw "Pinned Go module unavailable: $module ($($info.Error))" }
            if ($info.PSObject.Properties['Replace']) { throw "Unreviewed module replacement: $module" }
            foreach ($sum in @(@($module, $info.Sum), @(($module + '/go.mod'), $info.GoModSum))) {
                if ($lockedGoSums.ContainsKey($sum[0]) -and $lockedGoSums[$sum[0]] -cne $sum[1]) {
                    throw "Go source checksum differs from the pinned upstream go.sum: $module"
                }
            }
            # Go's file-proxy protocol escapes uppercase module letters as !lower.
            $relative = [regex]::Replace($module.Replace('@', '/@v/'), '[A-Z]', { param($match) '!' + $match.Value.ToLowerInvariant() })
            $record = [ordered]@{ module = $module; sum = $info.Sum; goModSum = $info.GoModSum; files = @() }
            foreach ($part in @(@('Zip', '.zip'), @('GoMod', '.mod'), @('Info', '.info'))) {
                $source = [string]$info.($part[0])
                Assert-NoLinks $source
                $targetRelative = 'third-party/go-modules/' + $relative + $part[1]
                $destination = Join-Path $payload $targetRelative
                [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination)) | Out-Null
                [IO.File]::Copy($source, $destination)
                $record.files += [ordered]@{ path = $targetRelative; sha256 = Hash $destination }
            }
            $moduleInventory.Add($record)
        }
    } finally { Pop-Location }
    Write-Json (Join-Path $thirdParty 'go-modules.json') @($moduleInventory.ToArray())

    # The Go module ZIP omits nested native submodules. Include the actual pinned
    # NaiveProxy/Chromium source, not just its URL or prebuilt libcronet binaries.
    $nativeCommit = 'be1be963131154ba82761a7ed85ba426b2027319'
    # Verified from git/commits/<nativeCommit>.tree.sha; tree IDs are not commit IDs.
    $nativeTreeHash = '8c9a82a312a04568bd58ec8addfd5f16dda19c12'
    $nativeSource = Join-Path $thirdParty "naiveproxy-$nativeCommit.tar.gz"
    Download "https://codeload.github.com/SagerNet/naiveproxy/tar.gz/$nativeCommit" $nativeSource
    $nativeTree = Invoke-RestMethod -Uri "https://api.github.com/repos/SagerNet/naiveproxy/git/trees/${nativeTreeHash}?recursive=1" -Headers @{ 'User-Agent' = 'MinTun-source-packaging' }
    if ($nativeTree.truncated -or $nativeTree.sha -cne $nativeTreeHash -or @($nativeTree.tree | Where-Object { $_.mode -eq '160000' }).Count) {
        throw 'Native source coverage requires review: truncated tree, wrong pinned tree, or nested submodules.'
    }
    Write-Json (Join-Path $thirdParty 'naiveproxy-tree.json') $nativeTree
    # Historical frontend preferred sources were reproduced using the exact
    # upstream Node/Yarn pins; every prebuilt asset matched byte-for-byte.
    $webCommit = '716e4fcc97759308f79875ff1809da945df70574'
    $webArchiveName = "tailscale-webclient-$webCommit-source.tar.gz"
    $webArchive = Join-Path $thirdParty $webArchiveName
    Download "https://codeload.github.com/tailscale/tailscale/tar.gz/$webCommit" $webArchive
    $webArchiveHash = '273f832db548bb0f38637c14e726d35b1a75219085d69290827a39c7f8d23241'
    if ((Hash $webArchive) -cne $webArchiveHash) { throw 'Historical frontend source checksum mismatch.' }
    $webProvenance = [ordered]@{
        prebuiltModule = 'github.com/tailscale/web-client-prebuilt@v0.0.0-20250124233751-d4cd19a26976'
        sourceCommit = $webCommit; sourceArchive = "third-party/$webArchiveName"; sourceSha256 = $webArchiveHash
        sourceDirectory = 'client/web'; node = '18.20.4'; yarn = '1.22.19'; vite = '5.1.7 (yarn.lock)'
        dependencySourceAccess = 'client/web/yarn.lock in the historical source archive gives exact public npm package URLs and integrity hashes; install with the unchanged lockfile. These general-purpose frontend dependencies are not copied from any private cache.'
        reproduction = @('Use the versions in tool/node.rev and tool/yarn.rev.', 'In client/web: yarn --no-default-rc --frozen-lockfile --non-interactive --ignore-scripts install', 'Then: node node_modules/vite/bin/vite.js build', 'Compare JS/CSS after decompressing the original prebuilt gzip assets; HTML and font compare directly.')
        measuredEvidence = 'The historical frontend-only build was exercised during release preparation, without changing shipped application/core/libbox binaries. All four original prebuilt assets matched byte-for-byte; the original JS gzip also occurs byte-for-byte in both shipped official desktop cores.'
        assets = @(
            [ordered]@{ path = 'assets/index-BbZBz4S-.js'; bytes = 284363; sha256 = '84ce7c297530705c18dd5ba8abadbd9b13e5cf0b803c9c268fa903b3a44ca14e' },
            [ordered]@{ path = 'assets/index-DVk8gqX9.css'; bytes = 43541; sha256 = '6158b0c2d0b0755b072d01abd89dbbb5f0a639073d99bbd586ed846ce2472461' },
            [ordered]@{ path = 'index.html'; bytes = 1796; sha256 = '329206698f2882cec38a917f7adac14615f7178ebf5936283f2e939fe214b358' },
            [ordered]@{ path = 'assets/Inter.var.latin-Dxq58mVK.woff2'; bytes = 37780; sha256 = '39e72c0794c12f2dbb14a0f61ca946b535f795b1478fcf795bd26e5cb52ded34' }
        )
    }
    Write-Json (Join-Path $thirdParty 'tailscale-webclient-build.json') $webProvenance
    # sing-tun embeds this signed DLL; supply its exact public driver source
    # and the distinct original signed-binary redistribution terms, never load it.
    $wintunCommit = 'bfef136abfa1665c2592be09a7e383d646cdbe6e'
    $wintunArchive = Join-Path $thirdParty "wintun-$wintunCommit-source.tar.gz"
    Download "https://codeload.github.com/WireGuard/wintun/tar.gz/$wintunCommit" $wintunArchive
    if ((Hash $wintunArchive) -cne '2895e3a80747e892f6846bb95f5dfd26aaec2927cdf8ef6cca6cc972ff7dde05') {
        throw 'Pinned Wintun 0.14.1 source checksum mismatch.'
    }
    $wintunNotice = Join-Path $thirdParty 'Wintun-0.14.1-prebuilt-binaries-license.txt'
    $noticeCache = Join-Path $root 'artifacts/v2.0.0-rust/source-notices/Wintun-0.14.1-prebuilt-binaries-license.txt'
    if (Test-Path -LiteralPath $noticeCache) { Assert-NoLinks $noticeCache; [IO.File]::Copy($noticeCache, $wintunNotice) }
    else { Download "https://raw.githubusercontent.com/WireGuard/wintun/$wintunCommit/prebuilt-binaries-license.txt" $wintunNotice }
    if ((Hash $wintunNotice) -cne '9aaf948856ce8845a762121306039ef09d0eeb4d9e4f4c355647d4081e818087') {
        throw 'Original Wintun signed-binary license checksum mismatch.'
    }
    # Exact debug-UI dependencies are pinned by upstream eventbus/fetch-htmx.go.
    # Their packages retain unminified JavaScript and original licenses.
    $debugSources = @(
        @('htmx.org', '2.0.4', 'sha512-HLxMCdfXDOJirs3vBZl/ZLoY+c7PfM4Ahr2Ad4YXh6d22T5ltbTXFFkpx9Tgb2vvmWFMbIc3LqN2ToNkZJvyYQ=='),
        @('htmx-ext-ws', '2.0.2', 'sha512-0eJEcwNlJwiAzaWwSJgbCVbTNF5cIBTPB05Zwr/5txvwyz3AGG7jYto5/wQ3sc0sJ9N2mSqDFXMC1yALKOLEtA==')
    )
    foreach ($dependency in $debugSources) {
        $name = $dependency[0]; $dependencyVersion = $dependency[1]
        $dependencyArchive = Join-Path $thirdParty "$name-$dependencyVersion.tgz"
        Download "https://registry.npmjs.org/$name/-/$name-$dependencyVersion.tgz" $dependencyArchive
        if ((Hash-Sri512 $dependencyArchive) -cne $dependency[2]) { throw "Pinned debug UI source checksum mismatch: $name" }
    }
    $htmxSourceCommit = 'b82cf843e47e575dd8c2ad8fee547d8e2c3bb87f'
    Download "https://codeload.github.com/bigskysoftware/htmx/tar.gz/$htmxSourceCommit" (Join-Path $thirdParty "htmx-$htmxSourceCommit-source.tar.gz")
    Push-Location $payload
    try {
        # Cargo verifies registry archive checksums against Cargo.lock; vendor retains
        # each dependency's licenses, build scripts, and linked native source files.
        $vendorConfig = @(& $Cargo vendor --locked --versioned-dirs 'vendor/rust')
        if ($LASTEXITCODE -ne 0) { throw 'Pinned Rust source vendoring failed.' }
        [IO.File]::AppendAllText((Join-Path $payload '.cargo/config.toml'), "`n" + ($vendorConfig -join "`n") + "`n", $utf8)
    } finally { Pop-Location }
    $null = @(Get-SafeFiles (Join-Path $payload 'vendor/rust'))
    $distribution = [ordered]@{
        version = $version
        applicationAllowlist = [ordered]@{ files = $files; trees = $trees }
        excludedWorkspaceInputs = @('DIAGNOSTICS*', 'examples', 'exe', '!TUN.bat', '.private', '.tools (except checksum-verified public dependencies)', 'target', 'build', 'bin', 'obj', 'history', 'screenshots', 'tests (except the explicitly allowlisted public verifier and synthetic protocol fixture)', 'state', 'invitations', 'keys', 'signing credentials', 'compiled applications')
        sources = [ordered]@{
            application = 'Cargo.toml/Cargo.lock, native, ui, assets, Android Java/resources/manifests, explicit build scripts'
            rust = 'vendor/rust: every locked registry crate, including Slint 1.18.1, checksummed by Cargo; .cargo/config.toml selects these sources'
            singBox = [ordered]@{ commit = '824dbcfb4dd0a95921840b1737b950cde590241e'; archive = 'third-party/sing-box-v1.15.0-alpha.13.tar.gz'; sha256 = $upstreamHash; buildInstructions = 'upstream .github/workflows/build.yml, release/DEFAULT_BUILD_TAGS*, release/LDFLAGS' }
            androidLibbox = [ordered]@{ archive = 'third-party/libbox-1.15.0-alpha.13-mintun-source.tar.gz'; sha256 = Hash (Join-Path $thirdParty 'libbox-1.15.0-alpha.13-mintun-source.tar.gz'); extension = 'scripts/android-libbox/mintun.go'; build = 'scripts/build-android-libbox.ps1'; provenance = 'third-party/libbox-build.json' }
            go = 'third-party/go-modules.json lists exact module source ZIP, go.mod, .info, module sums and SHA256; modules are selected by go list -deps (without tests) for the official Windows/Linux purego and macOS CGO release flags, both Android libbox ABIs, plus the pinned gomobile generator; native Cronet source is supplied separately from prebuilt lib modules'
            cronetGo = [ordered]@{ commit = 'b3c2ed82ac97b79cd051f7ec59ccbd2e014bb6de'; source = 'third-party/go-modules/github.com/sagernet/cronet-go/@v/v0.0.0-20261023060337-b3c2ed82ac97.zip'; nativeSubmoduleCommit = $nativeCommit; nativeArchive = "third-party/naiveproxy-$nativeCommit.tar.gz"; nativeSha256 = Hash $nativeSource; nativeTree = 'third-party/naiveproxy-tree.json'; nativeBuildInstructions = 'cronet-go cmd/build-naive and its upstream README; sing-box upstream build.yml pins library extraction to CRONET_GO_VERSION' }
            tailscaleWebAssets = $webProvenance
            wintun = [ordered]@{ version = '0.14.1'; sourceCommit = $wintunCommit; sourceArchive = "third-party/wintun-$wintunCommit-source.tar.gz"; binaryTerms = 'third-party/Wintun-0.14.1-prebuilt-binaries-license.txt'; sourceLicense = 'GPL-2.0, included in driver source COPYING'; buildInstructions = 'Driver source README and Visual Studio/WDK project files; official distribution uses signed DLLs. This packager never builds, installs or loads a driver.' }
            eventbusDebugUi = [ordered]@{ htmx = 'third-party/htmx.org-2.0.4.tgz'; htmxSourceCommit = $htmxSourceCommit; htmxPreferredSource = "third-party/htmx-$htmxSourceCommit-source.tar.gz"; websocket = 'third-party/htmx-ext-ws-2.0.2.tgz (includes original unminified ws.js)'; sourcePins = 'Pinned tailscale util/eventbus/fetch-htmx.go; tarballs verified against exact npm SHA512 integrity.' }
        }
        buildPrerequisites = [ordered]@{
            common = @('PowerShell 5.1 or newer', 'Rust >=1.92 (edition 2024), Cargo, required rustup target components', 'curl and tar on PATH', 'Network for official core artifacts/SDK tools; application Rust crate sources are vendored')
            windows = @('GNU target x86_64-pc-windows-gnu with MinGW-w64 GCC/binutils/windres on PATH (or MSVC target with Visual Studio Build Tools and Windows SDK)', 'scripts/build-desktop.ps1 -Target x86_64-pc-windows-gnu')
            linux = @('Native Linux build recommended: pkg-config, fontconfig/freetype development libraries, C/C++ toolchain, X11/Wayland development libraries', 'pwsh scripts/build-desktop.ps1 -Target x86_64-unknown-linux-gnu', 'Windows cross-build additionally needs cargo-zigbuild, Zig and a Linux fontconfig/freetype sysroot as required by build-desktop.ps1')
            macos = @('Native macOS host with genuine Xcode Command Line Tools and SDK, Rust x86_64-apple-darwin or aarch64-apple-darwin target, PowerShell, Go, curl and tar', 'pwsh scripts/build-desktop.ps1 -Target x86_64-apple-darwin or -Target aarch64-apple-darwin', 'App bundle uses ad-hoc signing, without Apple notarization; official bundled core hashes remain unchanged.')
            android = @('Windows host for supplied PowerShell scripts; JDK 17; Android SDK platform 35, build-tools 35.0.0, NDK 28.0.13004108; Rust aarch64-linux-android and x86_64-linux-android; cargo-ndk 4.1.2; Go (libbox provenance records exact original version); Gradle 8.11.1 and Android Gradle plugin pinned in android/build.gradle', 'scripts/build-android-libbox.ps1 -AndroidSdk <SDK> -JavaHome <JDK17> -Go <go.exe>', 'scripts/build-android.ps1 -Configuration Debug -AndroidSdk <SDK> -JavaHome <JDK17>', 'Release signing needs your own local signing identity; original publisher private keys are intentionally not distributed. android-signing.ps1 creates/maintains a local identity; no script is run by this packager.')
            upstreamCore = @('Official core upstream release workflow uses Go 1.26.10; exact tags/ldflags are supplied in the pinned sing-box source archive', 'Native Cronet requires upstream documented Chromium toolchain downloads and host prerequisites; full pruned NaiveProxy/Chromium source is supplied', 'For offline Go source access, expose supplied module .zip/.mod/.info files using the Go file-proxy layout (<module>/@v/<version>.*); go-modules.json carries module and checksum identities')
        }
        limitations = @('Source availability is not a claim of bit-for-bit binary reproducibility or a legal opinion.', 'Platform SDKs, system libraries, compiler toolchains and original private signing keys are not bundled.', 'Parent must verify exact final runtime files and source coverage before publishing. Native source tree metadata records upstream safe relative symlinks inside unextracted test data; the reused libbox archive is checked to contain exactly pristine public upstream source plus the reviewed adapter, without links.')
    }
    Write-Json (Join-Path $payload 'SOURCE-DISTRIBUTION.json') $distribution
    # Final inventory is deliberately outside the payload: it covers every ZIP file
    # member, including SOURCE-DISTRIBUTION.json, without a self-hash paradox.
    $manifest = @(
        foreach ($file in Get-SafeFiles $payload) {
            $relative = $file.FullName.Substring($payload.Length + 1).Replace('\', '/')
            [pscustomobject]@{ path = "MinTunClient-source-v$version/$relative"; size = $file.Length; sha256 = Hash $file.FullName }
        }
    ) | Sort-Object { $_.path }
    $base = "MinTunClient-source-v$version"
    $manifestPath = Join-Path $stage "$base.manifest.json"
    Write-Json $manifestPath $manifest
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    Add-Type -AssemblyName System.IO.Compression
    $archive = Join-Path $stage "$base.zip"
    # Write explicit forward-slash member names even on Windows PowerShell 5.1.
    # No directory entries are necessary; the manifest covers every ZIP member.
    $archiveStream = [IO.File]::Open($archive, [IO.FileMode]::CreateNew)
    try {
        $zip = [IO.Compression.ZipArchive]::new($archiveStream, [IO.Compression.ZipArchiveMode]::Create, $true)
        try {
            foreach ($member in $manifest) {
                $relative = $member.path.Substring($base.Length + 1)
                $source = Join-Path $payload $relative
                $entry = $zip.CreateEntry($member.path, [IO.Compression.CompressionLevel]::Optimal)
                $entry.LastWriteTime = [DateTimeOffset]::new(1980, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
                $inputStream = [IO.File]::OpenRead($source)
                try {
                    $entryStream = $entry.Open()
                    try { $inputStream.CopyTo($entryStream) }
                    finally { $entryStream.Dispose() }
                } finally { $inputStream.Dispose() }
            }
        } finally { $zip.Dispose() }
    } finally { $archiveStream.Dispose() }
    $summary = [ordered]@{ archive = "$base.zip"; size = (Get-Item -LiteralPath $archive).Length; sha256 = Hash $archive; members = @($manifest).Count; sourceBytes = ($manifest | Measure-Object -Property size -Sum).Sum; manifest = "$base.manifest.json"; manifestSha256 = Hash $manifestPath }
    $summaryPath = Join-Path $stage "$base.json"
    Write-Json $summaryPath $summary
    [IO.File]::WriteAllText((Join-Path $stage "$base.zip.sha256"), ($summary.sha256 + "  $base.zip`n"), $utf8)
    foreach ($name in @("$base.zip", "$base.manifest.json", "$base.json", "$base.zip.sha256")) {
        Publish-PreservingOld (Join-Path $stage $name) (Join-Path $output $name)
    }
    $summary | ConvertTo-Json
} finally {
    foreach ($key in $oldEnvironment.Keys) { [Environment]::SetEnvironmentVariable($key, $oldEnvironment[$key], 'Process') }
    # This invocation owns only this GUID stage; existing release outputs and backups survive.
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
}
