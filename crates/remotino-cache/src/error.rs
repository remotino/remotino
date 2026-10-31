//! Errors for the local cache.

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors produced by the cache.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The underlying SQLite operation failed.
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// A cached row could not be turned back into a chain entry.
    ///
    /// Not surfaced to the user as an error: the correct response to a corrupt cache is
    /// to discard it and resync, which [`crate::Cache::load_verified`] does. This variant
    /// exists so that path can distinguish "cache is bad" from "SQLite is broken".
    #[error("corrupt cache: {0}")]
    Corrupt(&'static str),

    /// A crypto-core error surfaced through a cache operation, e.g. a cached entry that
    /// fails canonical decode or a chain that no longer verifies.
    #[error("crypto: {0}")]
    Crypto(#[from] remotino_crypto::Error),
}
