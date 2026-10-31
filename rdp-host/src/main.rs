//! Remotino RDP sidecar.
//!
//! A standalone process that owns one RDP session. It exists as a separate binary because
//! IronRDP's CredSSP stack (sspi -> picky) pins a pre-release RustCrypto snapshot that
//! cannot share a binary with the main app's russh + remotino-crypto (stable RustCrypto).
//! Isolating it here keeps each dependency stack independently pinned.
//!
//! # Protocol (stdio, binary)
//!
//! The parent (the Tauri app) speaks to us over our stdin/stdout. stderr is logs.
//!
//! - **stdin**: newline-delimited JSON. The first line is the [`ConnectRequest`]; every
//!   line after is an [`InputMsg`] (mouse, keyboard, resize).
//! - **stdout**: length-prefixed binary frames: `[u32 len][u8 kind][payload]`.
//!   - kind 1 `FRAME`   : `[u16 x][u16 y][u16 w][u16 h][rgba…]` a decoded dirty rectangle.
//!   - kind 2 `SIZE`    : `[u16 w][u16 h]` the desktop size (sent once on connect).
//!   - kind 3 `STATUS`  : UTF-8 text (`"connected"`, `"error: …"`, `"closed"`).
//!
//! The password is read from stdin and never logged or echoed.

use anyhow::{Context as _, Result};
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt as _, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use ironrdp::connector::connection_activation::ConnectionActivationState;
use ironrdp::connector::{self, ClientConnector, Credentials};
use ironrdp::displaycontrol::client::DisplayControlClient;
use ironrdp::displaycontrol::pdu::MonitorLayoutEntry;
use ironrdp::dvc::DrdynvcClient;
use ironrdp::pdu::geometry::InclusiveRectangle;
use ironrdp::pdu::input::fast_path::{FastPathInputEvent, KeyboardFlags};
use ironrdp::pdu::input::mouse::{MousePdu, PointerFlags};
use ironrdp::pdu::rdp::capability_sets::MajorPlatformType;
use ironrdp::pdu::rdp::client_info::PerformanceFlags;
use ironrdp::pdu::WriteBuf;
use ironrdp::graphics::image_processing::PixelFormat;
use ironrdp::session::image::DecodedImage;
use ironrdp::session::{fast_path, ActiveStageBuilder, ActiveStageOutput};
use ironrdp_tokio::{Framed, FramedWrite as _};

mod clipboard;
mod proto;
use std::time::Duration;

use ironrdp::cliprdr::backend::ClipboardMessage;
use ironrdp::cliprdr::CliprdrClient;
use proto::OutWriter;

/// The first stdin line: everything needed to open the session.
#[derive(Debug, Deserialize)]
struct ConnectRequest {
    host: String,
    port: u16,
    username: String,
    password: String,
    #[serde(default)]
    domain: Option<String>,
    width: u16,
    height: u16,
    /// The server public-key fingerprint (SHA256 hex) this host was pinned to, if known.
    /// When set, the connection is refused if the server presents a different key.
    #[serde(default)]
    expected_key: Option<String>,
}

/// A subsequent stdin line: something the user did.
#[derive(Debug, Deserialize)]
#[serde(tag = "t")]
enum InputMsg {
    #[serde(rename = "m_move")]
    MouseMove { x: u16, y: u16 },
    #[serde(rename = "m_btn")]
    MouseButton { x: u16, y: u16, button: String, down: bool },
    #[serde(rename = "m_wheel")]
    MouseWheel { x: u16, y: u16, delta: i16 },
    #[serde(rename = "key")]
    Key { code: u8, down: bool, #[serde(default)] extended: bool },
    #[serde(rename = "resize")]
    Resize { w: u16, h: u16 },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    setup_logging();
    let mut out = OutWriter::new();

    if let Err(e) = run(&mut out).await {
        // Surface the reason to the parent, then exit non-zero.
        let _ = out.status(&format!("error: {e:#}")).await;
        std::process::exit(1);
    }
    Ok(())
}

async fn run(out: &mut OutWriter) -> Result<()> {
    // ---- read the connect request (first stdin line) ----
    let mut stdin = BufReader::new(tokio::io::stdin());
    let mut line = String::new();
    stdin.read_line(&mut line).await.context("read connect request")?;
    let req: ConnectRequest = serde_json::from_str(line.trim()).context("parse connect request")?;

    // ---- input pump: the rest of stdin -> a channel the session loop drains ----
    let (input_tx, mut input_rx) = mpsc::unbounded_channel::<InputMsg>();
    tokio::spawn(async move {
        let mut line = String::new();
        loop {
            line.clear();
            match stdin.read_line(&mut line).await {
                Ok(0) => break, // parent closed stdin
                Ok(_) => {
                    if let Ok(msg) = serde_json::from_str::<InputMsg>(line.trim()) {
                        if input_tx.send(msg).is_err() {
                            break;
                        }
                    }
                }
                Err(_) => break,
            }
        }
    });

    // ---- connect ----
    let mut clip = clipboard::ClipHandle::new();
    let poll_tx = clip.tx.clone();
    let config = build_config(&req);
    let server_name = req.host.clone();
    let (connection_result, mut framed, fingerprint) =
        connect(config, &server_name, req.port, clip.tx.clone())
            .await
            .context("connect")?;

    // Trust-on-first-use: refuse if the server key changed from what we pinned; report it on
    // first sight so the parent can store it.
    match &req.expected_key {
        Some(expected) if *expected != fingerprint => {
            out.status(&format!("certmismatch:{fingerprint}")).await?;
            anyhow::bail!("server key changed (possible MITM); expected {expected}, got {fingerprint}");
        }
        Some(_) => {} // matched
        None => out.status(&format!("hostkey:{fingerprint}")).await?, // first use
    }

    let width = connection_result.desktop_size.width;
    let height = connection_result.desktop_size.height;
    let mut image = DecodedImage::new(PixelFormat::RgbA32, width, height);

    // Retained to drive the Deactivation-Reactivation Sequence locally when the desktop
    // is resized (see the DeactivateAll arm below).
    let activation_factory = connection_result.activation_factory.clone();

    out.size(width, height).await?;
    out.status("connected").await?;

    // ---- active stage ----
    let mut active_stage = ActiveStageBuilder {
        static_channels: connection_result.static_channels,
        user_channel_id: connection_result.user_channel_id,
        io_channel_id: connection_result.io_channel_id,
        message_channel_id: connection_result.message_channel_id,
        share_id: connection_result.share_id,
        compression_type: connection_result.compression_type,
        enable_server_pointer: connection_result.enable_server_pointer,
        pointer_software_rendering: connection_result.pointer_software_rendering,
    }
    .build();

    // Poll the local clipboard for changes to advertise to the remote (~1.4 Hz).
    let mut clip_poll = tokio::time::interval(Duration::from_millis(700));
    #[cfg(any(windows, target_os = "macos"))]
    let mut clip_state = clipboard::ClipState::new();

    loop {
        tokio::select! {
            // Server -> us: decode graphics, echo back required response frames.
            pdu = framed.read_pdu() => {
                let (action, payload) = pdu.context("read pdu")?;
                let outputs = active_stage.process(&mut image, action, &payload).context("process")?;
                for out_item in outputs {
                    match out_item {
                        ActiveStageOutput::ResponseFrame(frame) => {
                            framed.write_all(&frame).await.context("write response")?;
                        }
                        ActiveStageOutput::GraphicsUpdate(region) => {
                            send_region(out, &image, &region).await?;
                        }
                        ActiveStageOutput::PointerBitmap(pointer) => {
                            out.cursor(
                                pointer.hotspot_x,
                                pointer.hotspot_y,
                                pointer.width,
                                pointer.height,
                                &pointer.bitmap_data,
                            )
                            .await?;
                        }
                        ActiveStageOutput::PointerHidden => out.cursor_hidden().await?,
                        ActiveStageOutput::PointerDefault => out.cursor_default().await?,
                        ActiveStageOutput::DeactivateAll => {
                            // The server is resizing (or otherwise reactivating). Drive the
                            // Deactivation-Reactivation Sequence to its new capabilities,
                            // then rebuild the framebuffer and fast-path processor at the new
                            // desktop size and tell the webview.
                            let mut seq = activation_factory.create();
                            let mut buf = WriteBuf::new();
                            loop {
                                ironrdp_tokio::single_sequence_step(&mut framed, &mut seq, &mut buf)
                                    .await
                                    .map_err(|e| anyhow::anyhow!("reactivation: {e}"))?;
                                if let ConnectionActivationState::Finalized {
                                    desktop_size,
                                    share_id,
                                    enable_server_pointer,
                                    pointer_software_rendering,
                                } = seq.connection_activation_state()
                                {
                                    image = DecodedImage::new(
                                        PixelFormat::RgbA32,
                                        desktop_size.width,
                                        desktop_size.height,
                                    );
                                    active_stage.set_fastpath_processor(
                                        fast_path::ProcessorBuilder {
                                            io_channel_id: seq.io_channel_id(),
                                            user_channel_id: seq.user_channel_id(),
                                            share_id,
                                            enable_server_pointer,
                                            pointer_software_rendering,
                                            bulk_decompressor: None,
                                        }
                                        .build(),
                                    );
                                    active_stage.set_share_id(share_id);
                                    active_stage.set_enable_server_pointer(enable_server_pointer);
                                    out.size(desktop_size.width, desktop_size.height).await?;
                                    break;
                                }
                            }
                        }
                        ActiveStageOutput::Terminate(_) => {
                            out.status("closed").await?;
                            return Ok(());
                        }
                        _ => {}
                    }
                }
            }

            // User -> us: translate to RDP input, write it.
            msg = input_rx.recv() => {
                let Some(msg) = msg else { continue };
                if let InputMsg::Resize { w, h } = &msg {
                    // Request a live resize over Display Control. The server answers with a
                    // Deactivation-Reactivation Sequence, handled in the DeactivateAll arm.
                    let (aw, ah) =
                        MonitorLayoutEntry::adjust_display_size(u32::from(*w), u32::from(*h));
                    if let Some(res) = active_stage.encode_resize(aw, ah, None, None) {
                        let frame = res.context("encode resize")?;
                        framed.write_all(&frame).await.context("write resize")?;
                    }
                    continue;
                }
                if let Some(event) = to_fastpath(&msg) {
                    let outputs = active_stage
                        .process_fastpath_input(&mut image, &[event])
                        .context("process input")?;
                    for out_item in outputs {
                        if let ActiveStageOutput::ResponseFrame(frame) = out_item {
                            framed.write_all(&frame).await.context("write input frame")?;
                        }
                    }
                }
            }

            // Clipboard backend -> remote: encode the outgoing CLIPRDR message and send it.
            clip_msg = clip.rx.recv() => {
                let Some(clip_msg) = clip_msg else { continue };
                if let Some(cliprdr) = active_stage.get_svc_processor_mut::<CliprdrClient>() {
                    let svc = match clip_msg {
                        ClipboardMessage::SendInitiateCopy(formats) => cliprdr.initiate_copy(&formats).ok(),
                        ClipboardMessage::SendFormatData(response) => cliprdr.submit_format_data(response).ok(),
                        ClipboardMessage::SendInitiatePaste(format) => cliprdr.initiate_paste(format).ok(),
                        _ => None,
                    };
                    if let Some(svc) = svc {
                        let frame = active_stage.process_svc_processor_messages(svc).context("cliprdr encode")?;
                        framed.write_all(&frame).await.context("write cliprdr")?;
                    }
                }
            }

            // Notice local clipboard changes and offer them to the remote.
            _ = clip_poll.tick() => {
                #[cfg(any(windows, target_os = "macos"))]
                clipboard::poll_local(&poll_tx, &mut clip_state);
            }
        }
    }
}

/// Sends one decoded dirty rectangle to the parent as a FRAME message.
///
/// `data_for_rect` returns a view into the full framebuffer: each row of the rectangle is
/// `desktop_width * 4` bytes apart, not tightly packed. We repack it into `w * h * 4`
/// contiguous bytes so the webview can drop it straight into an `ImageData`.
async fn send_region(out: &mut OutWriter, image: &DecodedImage, region: &InclusiveRectangle) -> Result<()> {
    let x = region.left;
    let y = region.top;
    let w = region.right.saturating_sub(region.left).saturating_add(1);
    let h = region.bottom.saturating_sub(region.top).saturating_add(1);

    let full_stride = usize::from(image.width()) * 4;
    let row_bytes = usize::from(w) * 4;
    let src = image.data_for_rect(region);

    let mut packed = Vec::with_capacity(row_bytes * usize::from(h));
    for row in 0..usize::from(h) {
        let off = row * full_stride;
        match src.get(off..off + row_bytes) {
            Some(slice) => packed.extend_from_slice(slice),
            None => break, // defensive: never index past the view
        }
    }
    out.frame(x, y, w, h, &packed).await
}

/// Translates one input message into a fast-path event. Resize is handled separately.
fn to_fastpath(msg: &InputMsg) -> Option<FastPathInputEvent> {
    match msg {
        InputMsg::MouseMove { x, y } => Some(FastPathInputEvent::MouseEvent(MousePdu {
            flags: PointerFlags::MOVE,
            number_of_wheel_rotation_units: 0,
            x_position: *x,
            y_position: *y,
        })),
        InputMsg::MouseButton { x, y, button, down } => {
            let mut flags = match button.as_str() {
                "right" => PointerFlags::RIGHT_BUTTON,
                "middle" => PointerFlags::MIDDLE_BUTTON_OR_WHEEL,
                _ => PointerFlags::LEFT_BUTTON,
            };
            if *down {
                flags |= PointerFlags::DOWN;
            }
            Some(FastPathInputEvent::MouseEvent(MousePdu {
                flags,
                number_of_wheel_rotation_units: 0,
                x_position: *x,
                y_position: *y,
            }))
        }
        InputMsg::MouseWheel { x, y, delta } => Some(FastPathInputEvent::MouseEvent(MousePdu {
            flags: PointerFlags::VERTICAL_WHEEL,
            number_of_wheel_rotation_units: *delta,
            x_position: *x,
            y_position: *y,
        })),
        InputMsg::Key { code, down, extended } => {
            let mut flags = if *down {
                KeyboardFlags::empty()
            } else {
                KeyboardFlags::RELEASE
            };
            if *extended {
                flags |= KeyboardFlags::EXTENDED;
            }
            Some(FastPathInputEvent::KeyboardEvent(flags, *code))
        }
        InputMsg::Resize { .. } => None,
    }
}

fn build_config(req: &ConnectRequest) -> connector::Config {
    connector::Config {
        credentials: Credentials::UsernamePassword {
            username: req.username.clone(),
            password: req.password.clone(),
        },
        domain: req.domain.clone(),
        enable_tls: true,
        enable_credssp: true,
        keyboard_type: ironrdp::pdu::gcc::KeyboardType::IbmEnhanced,
        keyboard_subtype: 0,
        keyboard_layout: 0,
        keyboard_functional_keys_count: 12,
        ime_file_name: String::new(),
        dig_product_id: String::new(),
        desktop_size: connector::DesktopSize {
            width: req.width,
            height: req.height,
        },
        bitmap: None,
        client_build: 0,
        client_name: "remotino".to_owned(),
        client_dir: "C:\\Windows\\System32\\mstscax.dll".to_owned(),
        platform: MajorPlatformType::WINDOWS,
        // Render the remote cursor ourselves (hardware/CSS cursor) rather than baking it
        // into the framebuffer: crisper and it tracks the local mouse without lag.
        enable_server_pointer: true,
        request_data: None,
        autologon: false,
        enable_audio_playback: false,
        // Bulk compression is broken upstream on reactivation; the spike proved not
        // advertising it keeps dynamic resize stable. RemoteFX (the codec that matters) is
        // negotiated regardless.
        compression_type: None,
        // false => emit pointer bitmaps for us to render (Accelerated, straight-alpha RGBA)
        // instead of drawing the cursor into the framebuffer.
        pointer_software_rendering: false,
        multitransport_flags: None,
        performance_flags: PerformanceFlags::default(),
        desktop_scale_factor: 0,
        hardware_id: None,
        license_cache: None,
        timezone_info: ironrdp::pdu::rdp::client_info::TimezoneInfo::default(),
        alternate_shell: String::new(),
        work_dir: String::new(),
    }
}

type SessionFramed = Framed<ironrdp_tokio::TokioStream<ironrdp_tls::TlsStream<TcpStream>>>;

async fn connect(
    config: connector::Config,
    server_name: &str,
    port: u16,
    clip_tx: tokio::sync::mpsc::UnboundedSender<ClipboardMessage>,
) -> Result<(connector::ConnectionResult, SessionFramed, String)> {
    let _ = &clip_tx;
    let tcp = TcpStream::connect((server_name, port)).await.context("tcp connect")?;
    let client_addr = tcp.local_addr().context("local addr")?;

    let mut framed = ironrdp_tokio::TokioFramed::new(tcp);

    // Register the Display Control dynamic channel so the desktop can be resized live.
    // Without it, `encode_resize` is a no-op and the resolution is fixed at connect time.
    let drdynvc =
        DrdynvcClient::new().with_dynamic_channel(DisplayControlClient::new(|_| Ok(Vec::new())));
    let mut connector = ClientConnector::new(config, client_addr).with_static_channel(drdynvc);

    // Register the CLIPRDR channel for text clipboard sharing (Windows + macOS).
    #[cfg(any(windows, target_os = "macos"))]
    {
        connector = connector.with_static_channel(clipboard::make_cliprdr(clip_tx));
    }

    let should_upgrade = ironrdp_tokio::connect_begin(&mut framed, &mut connector)
        .await
        .context("connect begin")?;

    let initial_stream = framed.into_inner_no_leftover();
    let (upgraded_stream, cert) = ironrdp_tls::upgrade(initial_stream, server_name)
        .await
        .context("tls upgrade")?;
    let server_public_key = ironrdp_tls::extract_tls_server_public_key(&cert)
        .context("server public key")?
        .to_owned();
    // Trust-on-first-use pin: the SHA256 of the server's public key, stable across restarts.
    let fingerprint = {
        use sha2::{Digest as _, Sha256};
        hex::encode(Sha256::digest(&server_public_key))
    };

    let upgraded = ironrdp_tokio::mark_as_upgraded(should_upgrade, &mut connector);
    let mut upgraded_framed = ironrdp_tokio::TokioFramed::new(upgraded_stream);

    let mut network_client = NoNetworkClient;
    let connection_result = ironrdp_tokio::connect_finalize(
        upgraded,
        connector,
        &mut upgraded_framed,
        &mut network_client,
        server_name.to_owned().into(),
        server_public_key,
        None,
    )
    .await
    .context("connect finalize")?;

    Ok((connection_result, upgraded_framed, fingerprint))
}

/// A no-op network client. CredSSP only calls this for Kerberos (KDC/proxy round-trips);
/// NTLM NLA against a workstation never does. Kerberos support is a later addition.
struct NoNetworkClient;

impl ironrdp_tokio::NetworkClient for NoNetworkClient {
    fn send(
        &mut self,
        _request: &connector::sspi::generator::NetworkRequest,
    ) -> impl std::future::Future<Output = connector::ConnectorResult<Vec<u8>>> {
        async {
            Err(ironrdp::connector::custom_err!(
                "network client",
                std::io::Error::other("Kerberos network requests are not supported by the sidecar yet")
            ))
        }
    }
}

fn setup_logging() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::builder()
        .with_default_directive(tracing::level_filters::LevelFilter::WARN.into())
        .with_env_var("RDP_HOST_LOG")
        .from_env_lossy();
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}
