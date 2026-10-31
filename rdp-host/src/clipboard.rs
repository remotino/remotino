//! Text clipboard bridge over the CLIPRDR channel.
//!
//! The sidecar is headless, so IronRDP's `WinClipboard` (which needs a window + message pump)
//! doesn't fit. Instead we implement a small [`CliprdrBackend`] directly against the OS
//! clipboard and *poll* it for local changes rather than listening for window messages.
//!
//! One backend, two platform text bindings ([`platform`]): Windows via `clipboard-win`, macOS
//! via `arboard` (NSPasteboard). Text only, both directions:
//! - **remote copy -> local**: `on_remote_copy` asks the remote for the text, `on_format_data_response`
//!   writes it to the local clipboard.
//! - **local copy -> remote**: the poller notices the local clipboard changed and advertises;
//!   `on_format_data_request` reads the local text and hands it back.

use ironrdp::cliprdr::backend::{ClipboardMessage, ClipboardMessageProxy};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

/// The queue of outgoing clipboard messages, drained by the session loop.
pub struct ClipHandle {
    pub tx: UnboundedSender<ClipboardMessage>,
    pub rx: UnboundedReceiver<ClipboardMessage>,
}

impl ClipHandle {
    pub fn new() -> Self {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        Self { tx, rx }
    }
}

/// Standard Windows clipboard format id for UTF-16 text (used on the wire on both platforms).
const CF_UNICODETEXT: u32 = 13;

/// Proxy the backend uses to enqueue outgoing messages for the session loop.
#[derive(Debug)]
pub struct Proxy {
    tx: UnboundedSender<ClipboardMessage>,
}

impl ClipboardMessageProxy for Proxy {
    fn send_clipboard_message(&self, message: ClipboardMessage) {
        let _ = self.tx.send(message);
    }
}

/// Platform-specific text access + local-change detection. Kept behind one interface so the
/// CLIPRDR backend below is identical on every platform.
#[cfg(windows)]
mod platform {
    /// Reads the local clipboard's text, if any.
    pub fn get_text() -> Option<String> {
        clipboard_win::get_clipboard_string().ok()
    }

    /// Sets the local clipboard text.
    pub fn set_text(text: &str) {
        let _ = clipboard_win::set_clipboard_string(text);
    }

    /// Local-change state: the Windows clipboard sequence number.
    pub struct ClipState(u32);

    impl ClipState {
        pub fn new() -> Self {
            Self(0)
        }
    }

    /// Whether the local clipboard changed since the last poll.
    pub fn changed(state: &mut ClipState) -> bool {
        let seq = clipboard_win::seq_num().map(|n| n.get()).unwrap_or(0);
        if seq != state.0 {
            state.0 = seq;
            true
        } else {
            false
        }
    }
}

#[cfg(target_os = "macos")]
mod platform {
    /// Reads the local clipboard's text, if any. A fresh `Clipboard` per call is cheap on
    /// macOS (it just wraps the general `NSPasteboard`).
    pub fn get_text() -> Option<String> {
        arboard::Clipboard::new().ok()?.get_text().ok()
    }

    /// Sets the local clipboard text.
    pub fn set_text(text: &str) {
        if let Ok(mut cb) = arboard::Clipboard::new() {
            let _ = cb.set_text(text.to_owned());
        }
    }

    /// Local-change state: the last text we saw. `NSPasteboard` has a change count, but
    /// `arboard` doesn't expose it, so we detect changes by comparing content - fine for text.
    pub struct ClipState(Option<String>);

    impl ClipState {
        pub fn new() -> Self {
            Self(None)
        }
    }

    /// Whether the local clipboard text changed since the last poll.
    pub fn changed(state: &mut ClipState) -> bool {
        let current = get_text();
        if current != state.0 {
            state.0 = current;
            true
        } else {
            false
        }
    }
}

#[cfg(any(windows, target_os = "macos"))]
mod imp {
    use super::{platform, Proxy, CF_UNICODETEXT};
    use ironrdp::cliprdr::backend::{ClipboardMessage, ClipboardMessageProxy as _, CliprdrBackend};
    use ironrdp::cliprdr::pdu::{
        ClipboardFormat, ClipboardFormatId, ClipboardGeneralCapabilityFlags, FormatDataRequest,
        FormatDataResponse, OwnedFormatDataResponse,
    };
    use ironrdp::core::IntoOwned as _;
    use tokio::sync::mpsc::UnboundedSender;

    pub use platform::ClipState;

    /// Text-only CLIPRDR backend over the OS clipboard.
    #[derive(Debug)]
    pub struct TextClipboard {
        proxy: Proxy,
    }

    impl TextClipboard {
        pub fn new(tx: UnboundedSender<ClipboardMessage>) -> Self {
            Self { proxy: Proxy { tx } }
        }
    }

    impl ironrdp::core::AsAny for TextClipboard {
        fn as_any(&self) -> &dyn core::any::Any {
            self
        }
        fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
            self
        }
    }

    impl CliprdrBackend for TextClipboard {
        fn temporary_directory(&self) -> &str {
            "."
        }

        fn client_capabilities(&self) -> ClipboardGeneralCapabilityFlags {
            ClipboardGeneralCapabilityFlags::empty()
        }

        fn on_ready(&mut self) {}

        fn on_request_format_list(&mut self) {
            // The remote wants our current formats. Advertise text if we have some.
            if platform::get_text().is_some() {
                self.proxy
                    .send_clipboard_message(ClipboardMessage::SendInitiateCopy(vec![
                        ClipboardFormat::new(ClipboardFormatId::new(CF_UNICODETEXT)),
                    ]));
            }
        }

        fn on_process_negotiated_capabilities(&mut self, _caps: ClipboardGeneralCapabilityFlags) {}

        fn on_remote_copy(&mut self, formats: &[ClipboardFormat]) {
            // The remote's clipboard changed. If it has text, ask for it.
            if formats
                .iter()
                .any(|f| f.id() == ClipboardFormatId::new(CF_UNICODETEXT))
            {
                self.proxy
                    .send_clipboard_message(ClipboardMessage::SendInitiatePaste(
                        ClipboardFormatId::new(CF_UNICODETEXT),
                    ));
            }
        }

        fn on_format_data_request(&mut self, _request: FormatDataRequest) {
            // The remote is pasting: give it our local text.
            let response = match platform::get_text() {
                Some(text) => FormatDataResponse::new_unicode_string(&text).into_owned(),
                None => OwnedFormatDataResponse::new_error(),
            };
            self.proxy
                .send_clipboard_message(ClipboardMessage::SendFormatData(response));
        }

        fn on_format_data_response(&mut self, response: FormatDataResponse<'_>) {
            // The remote sent the text we requested: put it on the local clipboard.
            if !response.is_error() {
                if let Ok(text) = response.to_unicode_string() {
                    platform::set_text(&text);
                }
            }
        }

        fn on_file_contents_request(&mut self, _request: ironrdp::cliprdr::pdu::FileContentsRequest) {}
        fn on_file_contents_response(
            &mut self,
            _response: ironrdp::cliprdr::pdu::FileContentsResponse<'_>,
        ) {
        }
        fn on_lock(&mut self, _data_id: ironrdp::cliprdr::pdu::LockDataId) {}
        fn on_unlock(&mut self, _data_id: ironrdp::cliprdr::pdu::LockDataId) {}
    }

    /// Builds the CLIPRDR client channel with our backend.
    pub fn make_cliprdr(tx: UnboundedSender<ClipboardMessage>) -> ironrdp::cliprdr::CliprdrClient {
        ironrdp::cliprdr::CliprdrClient::new(Box::new(TextClipboard::new(tx)))
    }

    /// If the local clipboard changed since the last poll and now holds text, enqueue an offer
    /// to the remote.
    pub fn poll_local(tx: &UnboundedSender<ClipboardMessage>, state: &mut ClipState) {
        if platform::changed(state) && platform::get_text().is_some() {
            let _ = tx.send(ClipboardMessage::SendInitiateCopy(vec![ClipboardFormat::new(
                ClipboardFormatId::new(CF_UNICODETEXT),
            )]));
        }
    }
}

#[cfg(any(windows, target_os = "macos"))]
pub use imp::{make_cliprdr, poll_local, ClipState};
