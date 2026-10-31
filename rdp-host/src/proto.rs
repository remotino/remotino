//! The stdout wire format the parent reads.
//!
//! Every message is length-prefixed: `[u32 total_len][u8 kind][payload]`, big-endian. One
//! writer, buffered, flushed after each message so the parent sees frames promptly.

use anyhow::{Context as _, Result};
use tokio::io::{AsyncWriteExt as _, BufWriter, Stdout};

/// Message kinds on the wire.
#[repr(u8)]
pub enum Kind {
    Frame = 1,
    Size = 2,
    Status = 3,
    /// A remote cursor shape: `[u16 hotspot_x][u16 hotspot_y][u16 w][u16 h][rgba…]`.
    Cursor = 4,
    /// Hide the cursor (empty payload).
    CursorHidden = 5,
    /// Restore the default cursor (empty payload).
    CursorDefault = 6,
}

/// Buffered writer over stdout that emits framed messages.
pub struct OutWriter {
    inner: BufWriter<Stdout>,
}

impl OutWriter {
    pub fn new() -> Self {
        Self {
            inner: BufWriter::new(tokio::io::stdout()),
        }
    }

    /// A decoded dirty rectangle: `[u16 x][u16 y][u16 w][u16 h][rgba…]`.
    pub async fn frame(&mut self, x: u16, y: u16, w: u16, h: u16, data: &[u8]) -> Result<()> {
        let mut payload = Vec::with_capacity(8 + data.len());
        payload.extend_from_slice(&x.to_be_bytes());
        payload.extend_from_slice(&y.to_be_bytes());
        payload.extend_from_slice(&w.to_be_bytes());
        payload.extend_from_slice(&h.to_be_bytes());
        payload.extend_from_slice(data);
        self.write_msg(Kind::Frame, &payload).await
    }

    /// The desktop size: `[u16 w][u16 h]`.
    pub async fn size(&mut self, w: u16, h: u16) -> Result<()> {
        let mut payload = Vec::with_capacity(4);
        payload.extend_from_slice(&w.to_be_bytes());
        payload.extend_from_slice(&h.to_be_bytes());
        self.write_msg(Kind::Size, &payload).await
    }

    /// A UTF-8 status line.
    pub async fn status(&mut self, text: &str) -> Result<()> {
        self.write_msg(Kind::Status, text.as_bytes()).await
    }

    /// A remote cursor shape (straight-alpha RGBA) with its hotspot.
    pub async fn cursor(&mut self, hx: u16, hy: u16, w: u16, h: u16, data: &[u8]) -> Result<()> {
        let mut payload = Vec::with_capacity(8 + data.len());
        payload.extend_from_slice(&hx.to_be_bytes());
        payload.extend_from_slice(&hy.to_be_bytes());
        payload.extend_from_slice(&w.to_be_bytes());
        payload.extend_from_slice(&h.to_be_bytes());
        payload.extend_from_slice(data);
        self.write_msg(Kind::Cursor, &payload).await
    }

    /// Hide the cursor.
    pub async fn cursor_hidden(&mut self) -> Result<()> {
        self.write_msg(Kind::CursorHidden, &[]).await
    }

    /// Restore the default cursor.
    pub async fn cursor_default(&mut self) -> Result<()> {
        self.write_msg(Kind::CursorDefault, &[]).await
    }

    async fn write_msg(&mut self, kind: Kind, payload: &[u8]) -> Result<()> {
        let total = u32::try_from(payload.len() + 1).context("message too large")?;
        self.inner.write_all(&total.to_be_bytes()).await?;
        self.inner.write_all(&[kind as u8]).await?;
        self.inner.write_all(payload).await?;
        self.inner.flush().await?;
        Ok(())
    }
}
