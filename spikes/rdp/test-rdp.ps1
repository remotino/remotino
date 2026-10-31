<#
.SYNOPSIS
    Interactive RDP performance test harness for the IronRDP spike.

.DESCRIPTION
    Launches ironrdp-viewer against a server so you can judge latency, codec behaviour
    and clipboard by hand. This is the Step 2 workhorse - run it repeatedly with
    different flags and record findings in RESULTS.md.

    The password is NOT accepted as a parameter. The viewer prompts for it interactively,
    which keeps it out of argv, shell history and the process list.

    A per-run log is written to logs/ with codec negotiation captured at debug level, so
    you can confirm which codec was actually used rather than assuming.

.EXAMPLE
    ./test-rdp.ps1 -RdpHost srv-db01 -Username Administrator
    ./test-rdp.ps1 -RdpHost srv-db01 -Username Administrator -Domain CORP -Perf
    ./test-rdp.ps1 -RdpHost srv-db01 -Username Administrator -Codecs 'remotefx:off'   # A/B the codec
    ./test-rdp.ps1 -RdpHost srv-db01 -Username Administrator -Size 2560x1440
#>
[CmdletBinding()]
param(
    [string]$RdpHost,
    [string]$Username,
    [string]$Domain,

    # Codec string passed to --codecs. RemoteFX is ON by default upstream; set
    # 'remotefx:off' to A/B it against plain bitmap and feel the difference.
    # Valid names: remotefx, qoi, qoiz.  (No H.264/AVC444 in IronRDP.)
    [string]$Codecs = 'remotefx:on',

    # WxH, e.g. 1920x1080. Omit to let the viewer pick.
    [string]$Size,

    [ValidateSet('enable', 'disable', 'stub')]
    [string]$Clipboard = 'enable',

    # Perf mode: stop rendering the server-side pointer (skips alpha blending).
    [switch]$Perf,

    # Bulk compression is OFF by default because IronRDP's decompression path produces
    # corrupt output (see RESULTS.md). Pass -Compression to re-test it against a newer
    # upstream; expect garbage until that is fixed.
    [switch]$Compression,

    # Fall back to legacy TLS auth if CredSSP/NLA is refused. Diagnostic only -
    # if you need this, note it in RESULTS.md as an NLA finding.
    [switch]$NoCredssp,

    # Raise log verbosity. Covers codec negotiation AND clipboard: without the cliprdr
    # crates listed here, clipboard problems leave no trace at all in the log.
    [string]$LogLevel = 'info,ironrdp_session=debug,ironrdp_connector=debug,ironrdp_cliprdr=trace,ironrdp_cliprdr_native=trace,ironrdp_svc=debug'
)

$ErrorActionPreference = 'Stop'

# Must match run-spike.ps1: the build lives on local disk when the repo is on a share.
# See the comment there for why.
function Get-WorkDir {
    if ($env:REMOTINO_WORK_DIR) { return $env:REMOTINO_WORK_DIR }
    $isNetwork = $false
    if ($PSScriptRoot -like '\\*') {
        $isNetwork = $true
    } else {
        $qualifier = (Split-Path -Qualifier $PSScriptRoot) -replace ':', ''
        $drive = Get-PSDrive -Name $qualifier -ErrorAction SilentlyContinue
        if ($drive -and $drive.DisplayRoot -like '\\*') { $isNetwork = $true }
    }
    if ($isNetwork) { return (Join-Path $env:LOCALAPPDATA 'Remotino\spike-work') }
    return (Join-Path $PSScriptRoot '.work')
}

$repoDir = Join-Path (Get-WorkDir) 'IronRDP'
$logDir  = Join-Path $PSScriptRoot 'logs'

function Write-Head { param($m) Write-Host "`n=== $m ===" -ForegroundColor Cyan }
function Write-Ok   { param($m) Write-Host "  [ok] $m" -ForegroundColor Green }
function Write-Warn { param($m) Write-Host "  [!!] $m" -ForegroundColor Yellow }

if (-not $RdpHost -or -not $Username) {
    Write-Host @'

test-rdp.ps1 - interactive RDP performance harness

  ./test-rdp.ps1 -RdpHost <host> -Username <user> [-Domain <dom>] [options]

  Options
    -Codecs <str>     default 'remotefx:on'. Try 'remotefx:off' to A/B.
                      Valid: remotefx, qoi, qoiz. No H.264 in IronRDP.
    -Size <WxH>       e.g. 2560x1440. Omit for the viewer default.
    -Clipboard <x>    enable (default) | disable | stub
    -Perf             skip server pointer rendering
    -Compression      re-enable bulk compression (broken upstream, expect garbage)
    -NoCredssp        legacy TLS auth instead of NLA (diagnostic only)

  What to test, in order of what would actually kill the design:
    1. Latency vs mstsc on the SAME link - open both, drag a window in each.
    2. Codec: run once with remotefx:on, once with remotefx:off. Feel the delta,
       and confirm in the log which one was negotiated.
    3. Clipboard text both ways, then an image.
    4. Resize the window - does the remote resolution follow?
    5. AltGr and your keyboard layout.
    6. Open 3-4 at once and watch CPU/RAM per session.

  Run it over the VPN/WAN link you actually use. LAN numbers prove nothing.

'@
    return
}

# --- prerequisites -----------------------------------------------------------
# Re-read machine + user PATH so toolchains installed after this shell started are
# visible without reopening the terminal.
$env:PATH = ([Environment]::GetEnvironmentVariable('Path', 'Machine'),
             [Environment]::GetEnvironmentVariable('Path', 'User'),
             "$env:USERPROFILE\.cargo\bin",
             $env:PATH) -join ';'

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw 'cargo not found - run: winget install Rustlang.Rustup'
}
if (-not (Test-Path $repoDir)) {
    throw "IronRDP not cloned. Run: ./run-spike.ps1 -Step setup"
}

# Prefer the already-built binary. `cargo run` re-resolves the whole workspace on every
# invocation, which adds seconds before each connection attempt and muddies the timing.
$viewerExe = Join-Path $repoDir 'target\release\ironrdp-viewer.exe'
if (-not (Test-Path $viewerExe)) {
    Write-Warn 'viewer binary not found - building it now (one time)'
    cargo build --manifest-path "$repoDir\Cargo.toml" --release --bin ironrdp-viewer
    if ($LASTEXITCODE -ne 0) { throw "viewer build failed (exit $LASTEXITCODE)" }
}

New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$stamp   = Get-Date -Format 'yyyyMMdd-HHmmss'
$logFile = Join-Path $logDir "$stamp-$RdpHost.log"

# --- assemble args -----------------------------------------------------------
$viewerArgs = @($RdpHost, '--username', $Username)
if ($Domain)        { $viewerArgs += @('--domain', $Domain) }
if ($Codecs)        { $viewerArgs += @('--codecs', $Codecs) }
if ($Clipboard)     { $viewerArgs += @('--clipboard-type', $Clipboard) }
if ($Perf)          { $viewerArgs += '--no-server-pointer' }
if (-not $Compression) { $viewerArgs += '--no-compression' }
if ($NoCredssp)     { $viewerArgs += '--no-credssp' }
$viewerArgs += @('--log-file', $logFile)

if ($Size) {
    if ($Size -notmatch '^\d+x\d+$') { throw "-Size must look like 1920x1080 (got '$Size')" }
    $w, $h = $Size -split 'x'
    $viewerArgs += @('--desktop-width', $w, '--desktop-height', $h)
}

Write-Head "Connecting to $RdpHost as $Username"
Write-Host "  codecs     : $Codecs"
Write-Host "  clipboard  : $Clipboard"
if ($Perf)          { Write-Host '  perf       : server pointer disabled' }
if ($Compression) { Write-Warn 'compression ENABLED - decode corruption expected' }
else { Write-Host '  compression: disabled (default)' }
if ($NoCredssp)     { Write-Warn 'CredSSP/NLA disabled - note this in RESULTS.md' }
Write-Host "  log        : $logFile"
Write-Host "`n  The viewer will prompt for the password (never passed on the command line)."

$env:RUST_LOG = $LogLevel

$sw = [Diagnostics.Stopwatch]::StartNew()

& $viewerExe @viewerArgs
$exit = $LASTEXITCODE

$sw.Stop()
Write-Head 'Session ended'
Write-Host ("  duration : {0:N1} s" -f $sw.Elapsed.TotalSeconds)
Write-Host  "  exit     : $exit"

# --- what codec actually got used -------------------------------------------
if (Test-Path $logFile) {
    Write-Head 'Codec negotiation (from log)'
    $hits = Select-String -Path $logFile -Pattern 'codec|remotefx|rfx|qoi|bitmap' -ErrorAction SilentlyContinue |
            Select-Object -First 15
    if ($hits) { $hits | ForEach-Object { "  $($_.Line.Trim())" } }
    else       { Write-Warn 'no codec lines matched - inspect the log by hand' }

    Write-Head 'Clipboard (from log)'
    $clip = Select-String -Path $logFile -Pattern 'cliprdr|clipboard|CLIPRDR' -ErrorAction SilentlyContinue |
            Select-Object -First 12
    if ($clip) { $clip | ForEach-Object { "  $($_.Line.Trim())" } }
    else {
        Write-Warn 'no clipboard lines at all - the CLIPRDR channel was probably never joined.'
        Write-Warn 'On Windows that is unexpected: a real WinClipboard backend should be built.'
    }

    Write-Head 'Errors / warnings'
    $errs = Select-String -Path $logFile -Pattern 'ERROR|WARN' -ErrorAction SilentlyContinue |
            Select-Object -First 15
    if ($errs) { $errs | ForEach-Object { "  $($_.Line.Trim())" } }
    else       { Write-Ok 'none' }

    Write-Host "`n  Full log: $logFile"
}

if ($exit -ne 0) {
    Write-Warn "viewer exited $exit - if this was an auth failure, try -NoCredssp to"
    Write-Warn 'isolate whether the problem is CredSSP/NLA specifically.'
}

Write-Host "`nRecord what you saw in RESULTS.md while it is fresh." -ForegroundColor Cyan
