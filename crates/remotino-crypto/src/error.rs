//! Error type for the crypto core.
//!
//! Deliberately coarse. Cryptographic failures must not explain *why* they failed in
//! detail: distinguishing "wrong passphrase" from "wrong key" from "tampered ciphertext"
//! hands an attacker an oracle. Callers get enough to act, no more.

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors produced by the crypto core.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Decryption or authentication failed.
    ///
    /// Covers a wrong passphrase, a wrong key, and tampered ciphertext alike - the
    /// distinction is withheld on purpose.
    #[error("decryption failed")]
    Decrypt,

    /// A signature did not verify against the claimed key.
    #[error("signature verification failed")]
    Signature,

    /// The audit chain is not internally consistent.
    #[error("chain integrity violated: {0}")]
    ChainIntegrity(&'static str),

    /// Input was structurally invalid - wrong length, unknown discriminant, malformed
    /// encoding.
    #[error("malformed input: {0}")]
    Malformed(&'static str),

    /// The repository declares a suite or version this build does not implement.
    #[error("unsupported: {0}")]
    Unsupported(&'static str),

    /// An escrow operation was refused because the configured [`EscrowScope`]
    /// excludes it.
    ///
    /// Distinct from [`Error::Malformed`] on purpose: this is a *policy* refusal on
    /// well-formed input, and callers may legitimately branch on it (e.g. "personal
    /// vaults are not escrowed here, skip the escrow wrap").
    ///
    /// [`EscrowScope`]: crate::escrow::EscrowScope
    #[error("escrow scope excludes: {0}")]
    EscrowScope(&'static str),

    /// Not enough escrow shares were supplied to meet the quorum.
    #[error("escrow quorum not met: {have} of {need} shares")]
    QuorumNotMet {
        /// Shares supplied.
        have: u8,
        /// Shares required.
        need: u8,
    },

    /// Serialisation or deserialisation failed.
    #[error("encoding: {0}")]
    Encoding(&'static str),
}
