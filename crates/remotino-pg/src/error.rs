//! Errors for the Postgres backend.

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors produced by the Postgres backend.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The database rejected the operation or the connection failed.
    #[error("postgres: {0}")]
    Db(#[from] tokio_postgres::Error),

    /// A stored row could not be turned back into a chain entry.
    ///
    /// Distinct from [`Error::Crypto`] so "the database gave us something we cannot parse"
    /// is never mistaken for a cryptographic failure - the first is corruption or version
    /// skew, the second is an attack or a bug.
    #[error("malformed row at seq {seq}: {reason}")]
    MalformedRow {
        /// Sequence number of the offending row.
        seq: i64,
        /// What was wrong with it.
        reason: &'static str,
    },

    /// A chain or crypto-core error surfaced through a repository operation.
    #[error("crypto: {0}")]
    Crypto(#[from] remotino_crypto::Error),

    /// The schema in the database is newer than this build understands.
    #[error("schema version {found} is newer than supported version {supported}")]
    SchemaTooNew {
        /// Version found in the database.
        found: i32,
        /// Highest version this build understands.
        supported: i32,
    },

    /// A database or role name was not a safe SQL identifier.
    ///
    /// Object names cannot be bound as parameters, so any name interpolated into DDL must
    /// be a strict identifier. Rejecting outright makes injection structurally impossible.
    #[error("invalid identifier: {0}")]
    BadIdentifier(String),

    /// The owned Tokio runtime could not be built.
    #[error("runtime: {0}")]
    Runtime(#[source] std::io::Error),

    /// Building the TLS client configuration failed.
    #[error("tls: {0}")]
    Tls(String),

    /// The server presented no certificate to inspect - most likely TLS is not enabled on it.
    #[error("the server did not present a TLS certificate (is TLS enabled on the server?)")]
    NoCertificate,

    /// The server certificate did not match the pinned (trusted) fingerprint - a possible
    /// man-in-the-middle, or the server's certificate was replaced.
    #[error("the server certificate does not match the trusted fingerprint")]
    CertMismatch,
}
