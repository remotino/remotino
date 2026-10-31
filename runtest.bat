@echo off
setlocal
cd /d "%~dp0"
title Remotino - runtest

REM  Double-click to build the RDP sidecar and launch the app (npm run tauri dev).
REM
REM  Usage:
REM    runtest.bat          normal run
REM    runtest.bat debug    verbose RDP engine logging (RDP_HOST_LOG=debug on stderr)
REM
REM  For a double-clickable debug run, use runtest-debug.bat.

if /I "%~1"=="debug" (
    set "RDP_HOST_LOG=debug"
    echo [runtest] RDP engine debug logging: ON
)

echo [runtest] Building the RDP sidecar ...
set "CARGO_TARGET_DIR=%LOCALAPPDATA%\Remotino\target-rdp"
cargo build --manifest-path "rdp-host\Cargo.toml"
if errorlevel 1 (
    echo [runtest] WARNING: sidecar build failed - a running RDP session can lock the
    echo [runtest]          binary. Continuing with the existing sidecar.
)

echo [runtest] Launching the app - npm run tauri dev ...
set "CARGO_TARGET_DIR=%LOCALAPPDATA%\Remotino\target"
cd remotino-app
call npm run tauri dev

echo.
echo [runtest] App exited.
pause
