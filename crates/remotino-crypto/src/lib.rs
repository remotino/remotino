//! Remotino cryptographic core.
//!
//! Phase 1 of the plan in `DESIGN.md`. This crate is deliberately free of I/O, UI and
//! platform code: it must be *correct* rather than fast, and it is far easier to review
//! and property-test in isolation. Nothing above it should be built until it is reviewed.
//!
//! # What lives here
//!
//! | Module | Responsibility | DESIGN.md |
//! |---|---|---|
//! | [`kdf`] | Argon2id parameters and passphrase derivation | 4 |
//! | [`identity`] | Ed25519 signing + X25519 wrapping keypairs, sealed at rest | 4 |
//! | [`envelope`] | Content keys and per-recipient wrapping | 4 |
//! | [`chain`] | Signed, hash-chained audit entries | 5 |
//! | [`escrow`] | k-of-n recovery, quorum growing with the admin count | 9.4a |
//! | [`repository`] | Storage abstraction so SQL can replace files later | 3, 8.2 |
//!
//! # The two properties everything rests on
//!
//! 1. **Permission is key possession.** With a shared file backend every user can read
//!    every byte, so an access-control list the application enforces is decorative. A
//!    folder is readable exactly by those whose public key its content key was wrapped
//!    to. See [`envelope`].
//!
//! 2. **The log is the database.** Audit records are not a parallel subsystem that can
//!    drift out of sync with the data; state is the fold of the signed chain, so an
//!    unaudited change is not representable. See [`chain`].
//!
//! # Cryptographic suite
//!
//! | Purpose | Primitive |
//! |---|---|
//! | Signing | Ed25519 |
//! | Key wrapping | X25519 (ML-KEM-768 hybrid reserved) |
//! | Content encryption | XChaCha20-Poly1305 |
//! | Passphrase KDF | Argon2id |
//! | Hashing | SHA-256 |
//!
//! RSA is deliberately absent; `DESIGN.md` 4 records why an 8192-bit RSA requirement was
//! not adopted. The suite is nonetheless recorded per-repository so it can be changed
//! without a format break.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
// The workspace denies unwrap/expect/panic/indexing because this crate parses data written
// by other people: a panic there is a remote crash. Tests are the opposite case - an
// unwrap is the assertion - so the ban is lifted only under cfg(test).
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )
)]

pub mod chain;
pub mod envelope;
pub mod error;
pub mod escrow;
pub mod identity;
pub mod kdf;
pub mod repository;

pub use error::{Error, Result};

/// Length of a SHA-256 digest, used for chain links and content addressing.
pub const DIGEST_LEN: usize = 32;

/// A SHA-256 digest.
///
/// A distinct type rather than a bare `[u8; 32]` so a chain link cannot be confused with
/// a key or a nonce at a call site.
#[derive(Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Digest(pub [u8; DIGEST_LEN]);

impl Digest {
    /// The all-zero digest, used as the `prev` link of the genesis entry.
    pub const ZERO: Self = Self([0u8; DIGEST_LEN]);

    /// Computes the SHA-256 digest of `bytes`, with no domain separation.
    ///
    /// Prefer [`Digest::tagged`] for anything whose digest participates in a security
    /// decision. This untagged form exists for interoperability and display; using it
    /// for two different kinds of object makes their digests collide across kinds.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        use sha2::Digest as _;
        let mut hasher = sha2::Sha256::new();
        hasher.update(bytes);
        Self(hasher.finalize().into())
    }

    /// Computes a domain-separated SHA-256 digest: `SHA-256(len(tag) || tag || bytes)`.
    ///
    /// The tag is length-prefixed so `("ab", "c")` and `("a", "bc")` cannot produce the
    /// same input stream. Used by the audit chain so an entry digest can never collide
    /// with a digest of some other kind of object that happens to share bytes.
    #[must_use]
    pub fn tagged(tag: &[u8], bytes: &[u8]) -> Self {
        use sha2::Digest as _;
        let mut hasher = sha2::Sha256::new();
        // usize -> u64 is lossless on every supported platform.
        hasher.update((tag.len() as u64).to_le_bytes());
        hasher.update(tag);
        hasher.update(bytes);
        Self(hasher.finalize().into())
    }
}

impl core::fmt::Debug for Digest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Short prefix: full digests make logs unreadable and add nothing when scanning.
        let prefix = self.0.get(..6).unwrap_or(&self.0);
        write!(f, "Digest({}..)", hex::encode(prefix))
    }
}

impl core::fmt::Display for Digest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}
