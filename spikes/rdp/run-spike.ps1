<#
.SYNOPSIS
    Spike A harness - builds and runs IronRDP's own example clients against a test host.

.DESCRIPTION
    Throwaway. Clones IronRDP into .work/ and runs its stock examples. We deliberately
    write no client code at this stage: the goal is to answer "does IronRDP talk to our
    servers" as cheaply as possible.

    Credential handling differs per step, because upstream forces our hand:

      screenshot - the example ONLY accepts -p/--password on argv. There is no env-var
                   path. argv is readable by other processes, so use a throwaway
                   account/password for this step, or prefer the viewer step.
      viewer     - prompts interactively; nothing lands in argv.

.EXAMPLE
    ./run-spike.ps1 -Step setup
    ./run-spike.ps1 -Step screenshot -RdpHost srv-test01 -Username you
    ./run-spike.ps1 -Step viewer     -RdpHost srv-test01 -Username you -Domain CORP
#>
[CmdletBinding()]
param(
    [ValidateSet('screenshot', 'viewer', 'setup')]
    [string]$Step,

    [string]$RdpHost,
    [string]$Username,
    [string]$Domain,

    # The example encodes PNG (the `image` crate is built with only the png feature),
    # so the extension must be .png.
    [string]$OutFile = "$PSScriptRoot/out.png",

    # Only used by -Step screenshot, which has no interactive prompt. Omit to be asked.
    [string]$Password,

    # Pin to a known-good tag for reproducibility; empty = default branch.
    [string]$IronRdpRef = ''
)

$ErrorActionPreference = 'Stop'

# The IronRDP clone and its multi-GB target/ must live on LOCAL disk. Cargo does
# thousands of small file operations and relies on file locking; over a network share that
# is painfully slow and the lock semantics are not dependable. If the repo itself is on a
# network share, redirect the build directory to local disk automatically.
# Override explicitly with REMOTINO_WORK_DIR.
function Get-WorkDir {
    if ($env:REMOTINO_WORK_DIR) { return $env:REMOTINO_WORK_DIR }

    $isNetwork = $false
    if ($PSScriptRoot -like '\\*') {
        $isNetwork = $true                       # UNC path
    } else {
        $qualifier = (Split-Path -Qualifier $PSScriptRoot) -replace ':', ''
        $drive = Get-PSDrive -Name $qualifier -ErrorAction SilentlyContinue
        if ($drive -and $drive.DisplayRoot -like '\\*') { $isNetwork = $true }  # mapped drive
    }

    if ($isNetwork) {
        $local = Join-Path $env:LOCALAPPDATA 'Remotino\spike-work'
        Write-Host "  [i] repo is on a network share - building in $local" -ForegroundColor DarkGray
        return $local
    }
    return (Join-Path $PSScriptRoot '.work')
}

$workDir = Get-WorkDir
$repoDir = Join-Path $workDir 'IronRDP'

function Write-Step { param($m) Write-Host "`n=== $m ===" -ForegroundColor Cyan }
function Write-Ok   { param($m) Write-Host "  [ok] $m" -ForegroundColor Green }
function Write-Warn { param($m) Write-Host "  [!!] $m" -ForegroundColor Yellow }

# --- usage -------------------------------------------------------------------
if (-not $Step) {
    Write-Host @'

Spike A - IronRDP viability harness

  Run the steps in order. Each is only worth doing if the previous one passed.

    ./run-spike.ps1 -Step setup
        Clone IronRDP and warm the build cache. First build takes 5-10 min.

    ./run-spike.ps1 -Step screenshot -RdpHost <host> -Username <user> [-Domain <dom>]
        Headless connect + decode to a PNG. Answers the riskiest question:
        does IronRDP speak protocol to our servers at all?
        NOTE: this example takes the password on argv - use a throwaway.

    ./run-spike.ps1 -Step viewer -RdpHost <host> -Username <user> [-Domain <dom>]
        Interactive session; prompts for the password. Work the README checklist.
        For repeated perf runs with codec switches, use test-rdp.ps1 instead.

  Record findings in RESULTS.md. Read README.md first for the GO/NO-GO bar.

'@
    return
}

# --- prerequisites -----------------------------------------------------------
Write-Step 'Checking prerequisites'

# Pick up toolchains installed after this shell started, so a fresh rustup/cmake
# install does not require reopening the terminal.
$env:PATH = ([Environment]::GetEnvironmentVariable('Path', 'Machine'),
             [Environment]::GetEnvironmentVariable('Path', 'User'),
             "$env:USERPROFILE\.cargo\bin",
             $env:PATH) -join ';'

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Warn 'Rust toolchain not found.'
    Write-Host @'
  Install it:

      winget install Rustlang.Rustup      # Windows
      curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh   # macOS

'@
    throw 'cargo not found'
}

$rustVer = (rustc --version) -replace '^rustc (\S+).*', '$1'
Write-Ok "rustc $rustVer  (IronRDP needs >= 1.89)"

if (-not (Get-Command git -ErrorAction SilentlyContinue)) { throw 'git not found' }

# --- source ------------------------------------------------------------------
Write-Step 'Fetching IronRDP'

if (-not (Test-Path $repoDir)) {
    New-Item -ItemType Directory -Force -Path $workDir | Out-Null
    git clone --depth 1 https://github.com/Devolutions/IronRDP.git $repoDir
} else {
    Write-Ok 'already cloned (delete .work/ to refresh)'
}

if ($IronRdpRef) {
    git -C $repoDir fetch --depth 1 origin $IronRdpRef
    git -C $repoDir checkout FETCH_HEAD
    Write-Ok "pinned to $IronRdpRef"
} else {
    Write-Warn 'running default branch - pin -IronRdpRef once you have a passing run'
}

# --- patches -----------------------------------------------------------------
# Must mirror run-spike.sh. Without this the Windows harness silently builds an
# UNPATCHED binary, which is exactly how the resize crash (patch 0002) came back after
# the build started running from a fresh clone.
$patchDir = Join-Path $PSScriptRoot 'patches'
if (Test-Path $patchDir) {
    Write-Step 'Applying local patches'
    foreach ($p in Get-ChildItem $patchDir -Filter '*.patch' | Sort-Object Name) {
        git -C $repoDir apply --check $p.FullName 2>$null
        if ($LASTEXITCODE -eq 0) {
            git -C $repoDir apply $p.FullName
            if ($LASTEXITCODE -eq 0) { Write-Ok "applied $($p.Name)" }
            else { Write-Warn "failed to apply $($p.Name)" }
        } else {
            git -C $repoDir apply --reverse --check $p.FullName 2>$null
            if ($LASTEXITCODE -eq 0) { Write-Ok "$($p.Name) already applied" }
            else { Write-Warn "$($p.Name) did not apply - upstream may have moved" }
        }
    }
}

# Features the screenshot example declares as required, added on top of the ironrdp
# crate's defaults (core + pdu). Do NOT pass --no-default-features here: it strips
# 'pdu', and the example imports ironrdp::pdu directly, so the build fails with E0433.
$shotFeatures = 'session,connector,graphics'

if ($Step -eq 'setup') {
    Write-Step 'Warming the build cache (first build is slow - 5-10 min)'

    Write-Host '  Building screenshot example (Step 1)...'
    cargo build --manifest-path "$repoDir/Cargo.toml" -p ironrdp --example screenshot `
        --release --features $shotFeatures
    if ($LASTEXITCODE -ne 0) { throw "screenshot build failed (exit $LASTEXITCODE)" }
    Write-Ok 'screenshot example built'

    Write-Host "`n  Building ironrdp-viewer (Step 2)..."
    Write-Host '  NOTE: upstream hardcodes the client-all feature, which pulls in opus'
    Write-Host '        and therefore needs cmake. If this fails, Step 1 still works;'
    Write-Host '        install cmake (winget install Kitware.CMake) to unblock Step 2.'
    cargo build --manifest-path "$repoDir/Cargo.toml" --release --bin ironrdp-viewer
    if ($LASTEXITCODE -ne 0) {
        Write-Warn "viewer build failed (exit $LASTEXITCODE) - Step 1 is still usable"
    } else {
        Write-Ok 'viewer built'
    }

    Write-Ok 'setup complete'
    return
}

# --- connection steps --------------------------------------------------------
if (-not $RdpHost)  { throw '-RdpHost is required' }
if (-not $Username) { throw '-Username is required' }

switch ($Step) {
    'screenshot' {
        # The example takes the password on argv only - no env-var path exists upstream.
        if (-not $Password) {
            $secure = Read-Host -AsSecureString "  RDP password (will be passed on argv)"
            $bstr   = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
            try     { $Password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
            finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        }

        $shotExe = Join-Path $repoDir 'target\release\examples\screenshot.exe'
        if (-not (Test-Path $shotExe)) { throw "screenshot.exe missing - run: ./run-spike.ps1 -Step setup" }

        $shotArgs = @('--host', $RdpHost, '-u', $Username, '-p', $Password, '-o', $OutFile)
        if ($Domain) { $shotArgs += @('-d', $Domain) }

        Write-Step "Step 1: headless connect + decode -> $OutFile"
        Write-Host '  Pass = a PNG that looks like the desktop.'
        Write-Host '  Fail = read the error carefully; usually NLA/CredSSP or TLS.'

        & $shotExe @shotArgs
        $exit = $LASTEXITCODE

        if ($exit -eq 0 -and (Test-Path $OutFile)) {
            $kb = [math]::Round((Get-Item $OutFile).Length / 1KB)
            Write-Ok "wrote $OutFile ($kb KB) - open it and confirm it is a real desktop"
        } else {
            Write-Warn "screenshot failed (exit $exit)"
        }
    }

    'viewer' {
        Write-Step 'Step 2: interactive session'
        Write-Host @'
  Work the checklist in README.md while connected. Specifically:
    - clipboard text BOTH directions, then an image
    - resize the window; does the remote resolution follow?
    - Ctrl+Alt+End, F-keys, AltGr characters
    - drop the network (disable the adapter) and watch the reconnect
    - open 3 more of these and watch CPU/RAM per session

  Run this over the VPN/WAN link you actually use. LAN numbers prove nothing.
  For repeated perf runs with codec switches, use test-rdp.ps1 instead.
'@
        $viewerExe = Join-Path $repoDir 'target\release\ironrdp-viewer.exe'
        if (-not (Test-Path $viewerExe)) { throw "ironrdp-viewer.exe missing - run: ./run-spike.ps1 -Step setup" }

        $vArgs = @($RdpHost, '--username', $Username)
        if ($Domain) { $vArgs += @('--domain', $Domain) }
        & $viewerExe @vArgs
    }
}

Write-Host "`nRecord what you saw in RESULTS.md while it is fresh." -ForegroundColor Cyan
