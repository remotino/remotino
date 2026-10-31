//! TLS with trust-on-first-use (TOFU) certificate pinning.
//!
//! Public CAs are the wrong trust model here: a shared Postgres repository usually runs on a
//! LAN with a self-signed certificate, and the security property we want is *this exact
//! server, unchanged since I first approved it* - the SSH known-hosts model, not the web PKI.
//!
//! So the verifier pins the server certificate by its SHA-256 fingerprint. On first connect
//! the app [`probe_certificate`]s the server, shows the human the fingerprint, and only after
//! they approve is the fingerprint stored in the connection profile. Every later connect
//! rejects anything that does not present that same certificate.
//!
//! Hostname verification is deliberately skipped: pinning the whole certificate is strictly
//! stronger, and LAN hosts rarely have a name that matches a certificate anyway.

use std::sync::{Arc, Mutex};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{ring, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio_postgres_rustls::MakeRustlsConnect;

use crate::{Error, Result};

/// A server certificate's identity, as shown to the user for approval.
#[derive(Debug, Clone)]
pub struct CertInfo {
    /// Raw SHA-256 of the DER-encoded leaf certificate.
    pub sha256: [u8; 32],
    /// The fingerprint as uppercase colon-separated hex (the form tools print).
    pub fingerprint: String,
    /// Certificate subject (e.g. `CN=db-server.corp`), or empty if it could not be parsed.
    pub subject: String,
    /// Certificate issuer.
    pub issuer: String,
    /// "Not before" validity bound, as a human-readable string.
    pub not_before: String,
    /// "Not after" validity bound.
    pub not_after: String,
}

impl CertInfo {
    fn from_der(der: &[u8]) -> Self {
        let sha256: [u8; 32] = Sha256::digest(der).into();
        let fingerprint = hex_colons(&sha256);
        // Parsing the rest is best-effort: the fingerprint is what the user actually pins;
        // subject/issuer/validity are just context. A parse failure must not lose the pin.
        let (subject, issuer, not_before, not_after) =
            match x509_parser::parse_x509_certificate(der) {
                Ok((_, cert)) => (
                    cert.subject().to_string(),
                    cert.issuer().to_string(),
                    cert.validity().not_before.to_string(),
                    cert.validity().not_after.to_string(),
                ),
                Err(_) => (String::new(), String::new(), String::new(), String::new()),
            };
        Self { sha256, fingerprint, subject, issuer, not_before, not_after }
    }
}

/// Uppercase colon-separated hex, e.g. `AB:CD:12:...` - the fingerprint form users compare.
fn hex_colons(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(3));
    for (i, b) in bytes.iter().enumerate() {
        if i != 0 {
            out.push(':');
        }
        out.push_str(&format!("{b:02X}"));
    }
    out
}

/// A slot the verifier writes the observed certificate into, so the caller can read it back
/// after the handshake (whether or not the handshake was allowed to complete).
type SeenSlot = Arc<Mutex<Option<CertInfo>>>;

/// Verifies the server certificate against a pinned SHA-256 fingerprint (TOFU).
#[derive(Debug)]
struct TofuVerifier {
    /// The trusted fingerprint. `None` means "not pinned yet".
    pinned: Option<[u8; 32]>,
    /// When true, accept any certificate (used only by [`probe_certificate`] to read the
    /// fingerprint for the approval prompt - never for a real data connection).
    probe: bool,
    /// Where the observed certificate is recorded for the caller.
    seen: SeenSlot,
    /// Signature-verification algorithms, so the handshake still proves the server holds the
    /// private key for the certificate it presented.
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for TofuVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> core::result::Result<ServerCertVerified, rustls::Error> {
        let info = CertInfo::from_der(end_entity.as_ref());
        let observed = info.sha256;
        if let Ok(mut slot) = self.seen.lock() {
            *slot = Some(info);
        }
        if self.probe {
            return Ok(ServerCertVerified::assertion());
        }
        match self.pinned {
            Some(pin) if pin == observed => Ok(ServerCertVerified::assertion()),
            Some(_) => Err(rustls::Error::General(
                "server certificate does not match the trusted fingerprint".to_owned(),
            )),
            None => Err(rustls::Error::General(
                "server certificate is not trusted yet (approve its fingerprint first)".to_owned(),
            )),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> core::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> core::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// Builds a tokio-postgres TLS connector that pins `pinned` (TOFU). Returns the connector and
/// the slot the observed certificate is recorded into. `probe` accepts any certificate and is
/// only for [`probe_certificate`].
fn make_connector(pinned: Option<[u8; 32]>, probe: bool) -> Result<(MakeRustlsConnect, SeenSlot)> {
    let provider = Arc::new(ring::default_provider());
    let algs = provider.signature_verification_algorithms;
    let seen: SeenSlot = Arc::new(Mutex::new(None));
    let verifier = Arc::new(TofuVerifier { pinned, probe, seen: seen.clone(), algs });

    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Tls(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    Ok((MakeRustlsConnect::new(config), seen))
}

/// A TLS connector that requires the server certificate to match `pinned`.
pub(crate) fn pinned_connector(pinned: Option<[u8; 32]>) -> Result<MakeRustlsConnect> {
    Ok(make_connector(pinned, false)?.0)
}

/// Connects to the server just far enough to read its certificate, without pinning anything,
/// and returns the certificate's identity for the user to approve. The returned handshake is
/// closed immediately - this never carries a data connection.
pub fn probe_certificate(config: &crate::PgConfig) -> Result<CertInfo> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(Error::Runtime)?;
    runtime.block_on(async {
        let (connector, seen) = make_connector(None, true)?;
        // Attempt to connect. The certificate is captured during the TLS handshake, before
        // authentication, so we get it even if the login is wrong or the server then closes
        // the connection - we deliberately ignore the connect result.
        let mut pg = config.to_pg(&config.database);
        pg.ssl_mode(tokio_postgres::config::SslMode::Require);
        let _ = pg.connect(connector).await;
        let info = seen.lock().ok().and_then(|mut s| s.take());
        info.ok_or(Error::NoCertificate)
    })
}
