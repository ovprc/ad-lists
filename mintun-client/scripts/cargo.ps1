param([Parameter(ValueFromRemainingArguments=$true)][string[]]$CargoArgs)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$portable = Join-Path $root '.tools\cargo\bin\cargo.exe'
if (Test-Path -LiteralPath $portable) {
    $env:CARGO_HOME = Join-Path $root '.tools\cargo'
    $env:RUSTUP_HOME = Join-Path $root '.tools\rustup'
    $env:PATH = "$(Join-Path $env:CARGO_HOME 'bin');$(Join-Path $root '.tools\w64devkit\bin');$(Join-Path $root '.tools\zig\ziglang');$env:PATH"
    $hostLibraries = Join-Path (& rustc --print sysroot) 'lib/rustlib/x86_64-pc-windows-gnu/lib/self-contained'
    if (Test-Path -LiteralPath $hostLibraries) {
        # Explicit --target does not apply target rustflags to host build scripts.
        $env:LIBRARY_PATH = "$hostLibraries;$env:LIBRARY_PATH"
    }
    $cargo = $portable
} else { $cargo = (Get-Command cargo -ErrorAction Stop).Source }
Push-Location $root
try {
    & $cargo @CargoArgs
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally { Pop-Location }
