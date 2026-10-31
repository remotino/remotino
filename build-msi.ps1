# One command to build the Windows MSI: the RDP sidecar (its own workspace) plus the Tauri
# app, bundled as a per-machine .msi with rdp-host.exe inside it.
#
#   .\build-msi.ps1
#
# Run from the repo root on Windows. Prereqs: Rust >= 1.89, Node, MSVC Build Tools, cmake.
# Tauri downloads the WiX toolset on the first MSI build (needs internet once, then caches it).

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

# Strip the build machine's home and source paths from the compiled binaries. Without this,
# rustc bakes C:\Users\<name>\.cargo\... (and the project path) into debug info and panic
# locations, which ship inside the .exe. Applies to both cargo builds below.
$env:RUSTFLAGS = "--remap-path-prefix=$env:USERPROFILE=/home/dev --remap-path-prefix=$PSScriptRoot=/src"

# 1. Build the sidecar into its OWN target dir - it pins a different dependency stack than the
#    app and cannot share a build.
Write-Host "==> [1/3] Building the RDP sidecar (rdp-host, release)..."
$env:CARGO_TARGET_DIR = "$env:LOCALAPPDATA\Remotino\target-rdp"
cargo build --release --manifest-path "rdp-host\Cargo.toml"
$rdp = "$env:LOCALAPPDATA\Remotino\target-rdp\release\rdp-host.exe"
if (-not (Test-Path $rdp)) { throw "rdp-host.exe not found at $rdp" }

# 2. Stage the sidecar where Tauri's externalBin expects it: named with the target triple, so
#    the bundler drops it next to the app exe (where the app looks for it at runtime).
$triple = ((rustc -vV | Select-String '^host:').Line -split '\s+')[1]
$binDir = "remotino-app\src-tauri\binaries"
New-Item -ItemType Directory -Force -Path $binDir | Out-Null
Copy-Item -Force $rdp (Join-Path $binDir "rdp-host-$triple.exe")
Write-Host "==> staged sidecar as rdp-host-$triple.exe"

# 3. Build the app + MSI. beforeBuildCommand rebuilds the frontend; externalBin bundles the
#    sidecar; bundle.targets = ["msi"] produces only the installer.
Write-Host "==> [2/3] Building the app and MSI (tauri build)..."
$env:CARGO_TARGET_DIR = "$env:LOCALAPPDATA\Remotino\target"
Push-Location remotino-app
try {
    if (-not (Test-Path node_modules)) { npm install }
    npx tauri build
}
finally {
    Pop-Location
}

Write-Host "==> [3/3] Done."
$msi = Get-ChildItem "$env:LOCALAPPDATA\Remotino\target\release\bundle\msi\*.msi" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime | Select-Object -Last 1
if ($null -eq $msi) { throw "MSI not found in the bundle output" }
Write-Host ("MSI: " + $msi.FullName)
Write-Host ("Size: {0:N1} MB" -f ($msi.Length / 1MB))
