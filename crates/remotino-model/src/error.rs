//! Errors for the domain model.

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors produced by folding or projecting events.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// An event payload could not be decoded.
    #[error("malformed event: {0}")]
    Malformed(&'static str),

    /// An event referenced a folder or entry that does not exist in the fold so far.
    ///
    /// A well-formed log never does this - a delete of a nonexistent entry, a grant on a
    /// missing folder. It means the log is inconsistent, which after chain verification
    /// should be impossible, so it is surfaced rather than ignored.
    #[error("event references unknown {0}")]
    DanglingReference(&'static str),

    /// A crypto operation failed while projecting - a wrap that would not unwrap, a blob
    /// that would not decrypt.
    #[error("crypto: {0}")]
    Crypto(#[from] remotino_crypto::Error),

    /// Serialisation failed.
    #[error("encoding: {0}")]
    Encoding(&'static str),
}
