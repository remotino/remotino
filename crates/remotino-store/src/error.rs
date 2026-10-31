//! Errors for the embedded store.

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors produced by the SQLite repository.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The underlying SQLite operation failed.
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// A stored row could not be turned back into a chain entry - corruption or a version
    /// skew, distinct from a crypto failure.
    #[error("malformed row at seq {seq}: {reason}")]
    MalformedRow {
        /// Sequence number of the offending row.
        seq: i64,
        /// What was wrong with it.
        reason: &'static str,
    },

    /// A crypto-core error surfaced through a store operation.
    #[error("crypto: {0}")]
    Crypto(#[from] remotino_crypto::Error),
}
