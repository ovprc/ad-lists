param([Parameter(ValueFromRemainingArguments=$true)][string[]]$PkgArgs)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$sysroot=$env:MINTUN_LINUX_SYSROOT
$triplet=$env:MINTUN_LINUX_TRIPLET
if (!$sysroot -or !$triplet) { throw 'Linux sysroot and target triplet are required.' }
$pkg=Join-Path (Split-Path $PSScriptRoot -Parent) '.tools/w64devkit/bin/pkg-config.exe'
# u-config has prefix relocation, but no PKG_CONFIG_SYSROOT_DIR support. Preserve
# real package/version metadata and relocate only its absolute include/lib flags.
$lines=@(& $pkg --dont-define-prefix "--define-variable=prefix=$sysroot/usr" "--define-variable=exec_prefix=$sysroot/usr" "--define-variable=libdir=$sysroot/usr/lib/$triplet" "--define-variable=includedir=$sysroot/usr/include" @PkgArgs)
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$flagRoot=$sysroot.Replace(' ','\ ')
foreach ($line in $lines) {
    [regex]::Replace([string]$line,'(?<flag>-(?:I|L))/usr(?=/|$)',{ param($m) $m.Groups['flag'].Value+$flagRoot+'/usr' })
}
