//! A live SSH session for the terminal: connect with russh, open a PTY-backed shell, and
//! pass the local terminal straight through to it.
//!
//! Mirrors the desktop app's russh flow (`remotino-app/src-tauri/src/ssh.rs`), but instead
//! of forwarding bytes to a webview it wires them to the real terminal's stdin/stdout. The
//! credential stays in this process - we never shell out to system `ssh`.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use russh::{client, ChannelMsg};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// How to authenticate.
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

/// Accepts the host key unconditionally, matching the app's current TOFU-less behaviour.
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

/// Connects, authenticates, opens a `cols`x`rows` PTY shell, and runs the passthrough until
/// the remote side closes. Assumes the terminal is already in raw mode.
pub async fn run(host: &str, port: u16, auth: Auth, cols: u16, rows: u16) -> Result<()> {
    let config = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(3600)),
        ..Default::default()
    });

    let mut handle = client::connect(config, (host, port), Handler)
        .await
        .with_context(|| format!("could not reach {host}:{port}"))?;

    let ok = match auth {
        Auth::Password { username, password } => handle
            .authenticate_password(username, password)
            .await
            .context("authentication error")?,
        Auth::Key {
            username,
            private_key,
            passphrase,
        } => {
            use russh::keys::ssh_key::PrivateKey;
            let mut key = PrivateKey::from_openssh(private_key.as_bytes())
                .map_err(|_| anyhow!("the linked credential is not a valid OpenSSH key"))?;
            if key.is_encrypted() {
                let pass = passphrase.ok_or_else(|| anyhow!("this key needs a passphrase"))?;
                key = key
                    .decrypt(pass.as_bytes())
                    .map_err(|_| anyhow!("wrong key passphrase"))?;
            }
            let hash = handle
                .best_supported_rsa_hash()
                .await
                .context("authentication error")?
                .flatten();
            let key = russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), hash);
            handle
                .authenticate_publickey(username, key)
                .await
                .context("authentication error")?
        }
    };
    if !ok.success() {
        bail!("authentication failed");
    }

    let channel = handle.channel_open_session().await.context("open channel")?;
    channel
        .request_pty(
            false,
            "xterm-256color",
            u32::from(cols.max(1)),
            u32::from(rows.max(1)),
            0,
            0,
            &[],
        )
        .await
        .context("request pty")?;
    channel.request_shell(true).await.context("request shell")?;

    passthrough(channel, (cols, rows)).await?;
    drop(handle); // disconnect
    Ok(())
}

/// Forwards local stdin to the channel and channel output to stdout, tracking terminal
/// resizes by polling the size (cross-platform; no signal handling needed).
async fn passthrough(mut channel: russh::Channel<client::Msg>, start: (u16, u16)) -> Result<()> {
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut buf = [0u8; 8192];

    let mut size_poll = tokio::time::interval(Duration::from_millis(300));
    let mut last_size = start;

    loop {
        tokio::select! {
            msg = channel.wait() => {
                match msg {
                    Some(ChannelMsg::Data { data }) => {
                        stdout.write_all(&data).await?;
                        stdout.flush().await?;
                    }
                    Some(ChannelMsg::ExtendedData { data, .. }) => {
                        stdout.write_all(&data).await?;
                        stdout.flush().await?;
                    }
                    Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => break,
                    _ => {}
                }
            }
            read = stdin.read(&mut buf) => {
                match read {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if channel.data(&buf[..n]).await.is_err() { break; }
                    }
                }
            }
            _ = size_poll.tick() => {
                if let Ok(size) = crossterm::terminal::size() {
                    if size != last_size {
                        last_size = size;
                        let _ = channel
                            .window_change(u32::from(size.0.max(1)), u32::from(size.1.max(1)), 0, 0)
                            .await;
                    }
                }
            }
        }
    }
    let _ = channel.eof().await;
    Ok(())
}
