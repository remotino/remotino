//! Live SSH sessions: the Rust half of a terminal tab.
//!
//! One [`connect`] spins up an authenticated russh session, opens a PTY-backed shell, and
//! moves both the client handle and the channel into a dedicated task. That task is the
//! only owner of the channel; everything else talks to it through an mpsc [`Cmd`] queue.
//! This sidesteps the split-read/split-write problem: the task selects between *channel
//! output* (which it forwards to the webview as `ssh://data` events) and *input commands*
//! (bytes to write, resizes, close) coming from the UI.
//!
//! Passwords are handled here only for the duration of the connect call - they are never
//! stored, never logged, and never sent back to the webview. The credential vault
//! (`DESIGN.md` 4) will later feed these without the user re-typing; until it exists, the
//! UI prompts interactively, exactly as any SSH client does.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use russh::client;
use russh::ChannelMsg;
use serde::Serialize;
use tauri::{AppHandle, Emitter};
use tokio::sync::mpsc;

/// How to authenticate an SSH session.
pub enum Auth {
    /// Username + password.
    Password { username: String, password: String },
    /// Username + an OpenSSH private key (with an optional passphrase).
    Key {
        username: String,
        private_key: String,
        passphrase: Option<String>,
    },
}

/// A message from the UI to a live session's owning task.
enum Cmd {
    /// Bytes typed by the user, to write to the remote shell.
    Data(Vec<u8>),
    /// The terminal was resized to `cols` x `rows`.
    Resize(u32, u32),
    /// Close the session.
    Close,
}

/// Registry of live sessions: id -> the queue into its owning task. Dropped on close/EOF.
#[derive(Default)]
pub struct Sessions {
    inner: Mutex<HashMap<String, mpsc::UnboundedSender<Cmd>>>,
}

impl Sessions {
    fn insert(&self, id: String, tx: mpsc::UnboundedSender<Cmd>) {
        if let Ok(mut map) = self.inner.lock() {
            map.insert(id, tx);
        }
    }
    fn send(&self, id: &str, cmd: Cmd) {
        if let Ok(map) = self.inner.lock() {
            if let Some(tx) = map.get(id) {
                let _ = tx.send(cmd);
            }
        }
    }
    fn remove(&self, id: &str) {
        if let Ok(mut map) = self.inner.lock() {
            map.remove(id);
        }
    }
}

/// The event payload for a chunk of terminal output. Bytes as-is; the webview decodes.
#[derive(Clone, Serialize)]
struct DataEvent {
    bytes: Vec<u8>,
}

/// russh needs a handler for server-side events. We accept the host key unconditionally for
/// now; known-hosts / TOFU pinning is a later hardening step, tracked with the vault work.
struct Handler;

impl client::Handler for Handler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// Connects, authenticates with a password, opens a shell, and starts the pump task.
///
/// Returns the new session id the UI uses for `send`/`resize`/`close` and to filter the
/// `ssh://data/<id>` and `ssh://closed/<id>` events. All failures collapse to a short
/// string - enough for the UI, nothing a bad actor can mine.
pub async fn connect(
    app: AppHandle,
    sessions: Arc<Sessions>,
    id: String,
    host: String,
    port: u16,
    auth: Auth,
    cols: u32,
    rows: u32,
) -> Result<(), String> {
    let config = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(3600)),
        ..Default::default()
    });

    let mut handle = client::connect(config, (host.as_str(), port), Handler)
        .await
        .map_err(|e| format!("connect failed: {e}"))?;

    let result = match auth {
        Auth::Password { username, password } => handle
            .authenticate_password(username, password)
            .await
            .map_err(|e| format!("auth error: {e}"))?,
        Auth::Key {
            username,
            private_key,
            passphrase,
        } => {
            use russh::keys::ssh_key::PrivateKey;
            let mut key = PrivateKey::from_openssh(private_key.as_bytes())
                .map_err(|_| "not a valid OpenSSH private key".to_owned())?;
            if key.is_encrypted() {
                let pass = passphrase.ok_or("this key needs a passphrase")?;
                key = key
                    .decrypt(pass.as_bytes())
                    .map_err(|_| "wrong key passphrase".to_owned())?;
            }
            let hash = handle
                .best_supported_rsa_hash()
                .await
                .map_err(|e| format!("auth error: {e}"))?
                .flatten();
            let key = russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), hash);
            handle
                .authenticate_publickey(username, key)
                .await
                .map_err(|e| format!("auth error: {e}"))?
        }
    };
    if !result.success() {
        return Err("authentication failed".to_owned());
    }

    let mut channel = handle
        .channel_open_session()
        .await
        .map_err(|e| format!("channel error: {e}"))?;
    channel
        .request_pty(false, "xterm-256color", cols.max(1), rows.max(1), 0, 0, &[])
        .await
        .map_err(|e| format!("pty error: {e}"))?;
    channel
        .request_shell(true)
        .await
        .map_err(|e| format!("shell error: {e}"))?;

    let (tx, mut rx) = mpsc::unbounded_channel::<Cmd>();
    sessions.insert(id.clone(), tx);

    // The pump task owns `handle` (keeping the session alive) and `channel`. It is the sole
    // reader and writer of the channel, so no locking is needed around it.
    tauri::async_runtime::spawn(async move {
        let data_ev = format!("ssh://data/{id}");
        let closed_ev = format!("ssh://closed/{id}");
        loop {
            tokio::select! {
                msg = channel.wait() => {
                    match msg {
                        Some(ChannelMsg::Data { data }) => {
                            let _ = app.emit(&data_ev, DataEvent { bytes: data.to_vec() });
                        }
                        Some(ChannelMsg::ExtendedData { data, .. }) => {
                            let _ = app.emit(&data_ev, DataEvent { bytes: data.to_vec() });
                        }
                        Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => break,
                        _ => {}
                    }
                }
                cmd = rx.recv() => {
                    match cmd {
                        Some(Cmd::Data(bytes)) => {
                            if channel.data(bytes.as_slice()).await.is_err() { break; }
                        }
                        Some(Cmd::Resize(c, r)) => {
                            let _ = channel.window_change(c.max(1), r.max(1), 0, 0).await;
                        }
                        Some(Cmd::Close) | None => {
                            let _ = channel.eof().await;
                            break;
                        }
                    }
                }
            }
        }
        let _ = app.emit(&closed_ev, &id);
        sessions.remove(&id);
        // `handle` drops here, disconnecting the session.
        drop(handle);
    });

    Ok(())
}

/// Forwards typed bytes to a live session.
pub fn send(sessions: &Sessions, id: &str, bytes: Vec<u8>) {
    sessions.send(id, Cmd::Data(bytes));
}

/// Tells a live session its terminal was resized.
pub fn resize(sessions: &Sessions, id: &str, cols: u32, rows: u32) {
    sessions.send(id, Cmd::Resize(cols, rows));
}

/// Closes a live session.
pub fn close(sessions: &Sessions, id: &str) {
    sessions.send(id, Cmd::Close);
}
