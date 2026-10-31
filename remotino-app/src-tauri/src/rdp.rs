//! Bridge to the RDP sidecar (`rdp-host`).
//!
//! The RDP engine can't share this binary (its IronRDP/sspi crypto stack conflicts with
//! russh + remotino-crypto), so it runs as a child process. This module spawns one child per
//! session, feeds it the connect request and input events on its stdin, and forwards the
//! framebuffer messages it writes on its stdout straight to the webview as raw bytes over a
//! Tauri channel - binary all the way to the canvas, no per-frame JSON.
//!
//! Wire format is defined in `rdp-host/README.md`. We are format-agnostic here: each stdout
//! message is `[u32 len][len bytes]`, and we hand those `len` bytes (a `[kind][payload]`
//! blob) to the webview verbatim.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Mutex;

use serde::Serialize;
use tauri::ipc::{Channel, InvokeResponseBody};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;

/// A message from the UI to a live session's writer task.
enum Cmd {
    /// A JSON input line (already serialised) to write to the sidecar's stdin.
    Input(String),
    /// Tear the session down.
    Close,
}

/// Live RDP sessions: id -> the queue into its owning tasks.
#[derive(Default)]
pub struct Sessions {
    inner: Mutex<HashMap<String, mpsc::UnboundedSender<Cmd>>>,
}

impl Sessions {
    fn insert(&self, id: String, tx: mpsc::UnboundedSender<Cmd>) {
        if let Ok(mut m) = self.inner.lock() {
            m.insert(id, tx);
        }
    }
    fn send(&self, id: &str, cmd: Cmd) {
        if let Ok(m) = self.inner.lock() {
            if let Some(tx) = m.get(id) {
                let _ = tx.send(cmd);
            }
        }
    }
    fn remove(&self, id: &str) {
        if let Ok(mut m) = self.inner.lock() {
            m.remove(id);
        }
    }
}

/// The connect request the sidecar expects as its first stdin line.
#[derive(Serialize)]
struct ConnectRequest<'a> {
    host: &'a str,
    port: u16,
    username: &'a str,
    password: &'a str,
    domain: Option<&'a str>,
    width: u16,
    height: u16,
    expected_key: Option<&'a str>,
}

/// Spawns the sidecar for a session and starts pumping it.
///
/// `on_event` receives every sidecar stdout message as raw bytes. The password is written to
/// the child's stdin and never stored here.
#[allow(clippy::too_many_arguments)]
pub async fn connect(
    sessions: std::sync::Arc<Sessions>,
    id: String,
    host: String,
    port: u16,
    username: String,
    password: String,
    domain: Option<String>,
    width: u16,
    height: u16,
    expected_key: Option<String>,
    known_hosts_path: Option<PathBuf>,
    on_event: Channel<InvokeResponseBody>,
) -> Result<(), String> {
    let exe = sidecar_path();
    let mut cmd = Command::new(&exe);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    // The sidecar is a console app; without this Windows gives it its own console window that
    // pops up on every RDP connect. CREATE_NO_WINDOW (0x08000000) suppresses it.
    #[cfg(windows)]
    cmd.creation_flags(0x0800_0000);
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("failed to launch RDP engine ({}): {e}", exe.display()))?;

    let mut stdin = child.stdin.take().ok_or("no sidecar stdin")?;
    let stdout = child.stdout.take().ok_or("no sidecar stdout")?;

    // Send the connect request as the first line.
    let req = ConnectRequest {
        host: &host,
        port,
        username: &username,
        password: &password,
        domain: domain.as_deref(),
        width,
        height,
        expected_key: expected_key.as_deref(),
    };
    let mut line = serde_json::to_string(&req).map_err(|e| e.to_string())?;
    line.push('\n');
    stdin
        .write_all(line.as_bytes())
        .await
        .map_err(|e| format!("write connect request: {e}"))?;

    let (tx, mut rx) = mpsc::unbounded_channel::<Cmd>();
    sessions.insert(id.clone(), tx);

    // Writer task: owns stdin and the child. Forwards input lines; kills the child on Close.
    tauri::async_runtime::spawn(async move {
        while let Some(cmd) = rx.recv().await {
            match cmd {
                Cmd::Input(mut json) => {
                    json.push('\n');
                    if stdin.write_all(json.as_bytes()).await.is_err() {
                        break;
                    }
                }
                Cmd::Close => break,
            }
        }
        let _ = child.kill().await;
    });

    // Reader task: owns stdout. Reads `[u32 len][len bytes]` frames, forwards the bytes.
    let sessions_r = std::sync::Arc::clone(&sessions);
    tauri::async_runtime::spawn(async move {
        let mut reader = BufReader::new(stdout);
        loop {
            let mut len_buf = [0u8; 4];
            if reader.read_exact(&mut len_buf).await.is_err() {
                break;
            }
            let len = u32::from_be_bytes(len_buf) as usize;
            let mut buf = vec![0u8; len];
            if reader.read_exact(&mut buf).await.is_err() {
                break;
            }
            // Intercept the first-use key report (STATUS "hostkey:<fp>"): pin it and don't
            // forward it - it is internal trust bookkeeping, not something the UI shows.
            if buf.first() == Some(&3) {
                if let Ok(text) = std::str::from_utf8(&buf[1..]) {
                    if let Some(fp) = text.strip_prefix("hostkey:") {
                        if let Some(path) = &known_hosts_path {
                            crate::known_hosts::set(path, &host, fp);
                        }
                        continue;
                    }
                }
            }
            if on_event.send(InvokeResponseBody::Raw(buf)).is_err() {
                break;
            }
        }
        // The sidecar's stdout closed (it exited): tell the UI with a synthetic STATUS so it
        // can decide whether to reconnect. A preceding "closed"/"error" says why.
        let mut ended = vec![3u8];
        ended.extend_from_slice(b"ended");
        let _ = on_event.send(InvokeResponseBody::Raw(ended));
        sessions_r.remove(&id);
    });

    Ok(())
}

/// Forwards a JSON input event (already the sidecar's schema) to a live session.
pub fn input(sessions: &Sessions, id: &str, event_json: String) {
    sessions.send(id, Cmd::Input(event_json));
}

/// Closes a live session (kills the sidecar).
pub fn close(sessions: &Sessions, id: &str) {
    sessions.send(id, Cmd::Close);
}

/// Locates the sidecar binary, in priority order:
/// 1. the `REMOTINO_RDP_HOST` override,
/// 2. next to the app executable (a bundled deployment),
/// 3. the dev build path under `%LOCALAPPDATA%`.
fn sidecar_path() -> PathBuf {
    if let Ok(p) = std::env::var("REMOTINO_RDP_HOST") {
        return PathBuf::from(p);
    }
    let exe_name = if cfg!(windows) { "rdp-host.exe" } else { "rdp-host" };
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join(exe_name);
            if candidate.exists() {
                return candidate;
            }
        }
    }
    let base = std::env::var("LOCALAPPDATA").unwrap_or_default();
    PathBuf::from(base)
        .join("Remotino")
        .join("target-rdp")
        .join("debug")
        .join("rdp-host.exe")
}
