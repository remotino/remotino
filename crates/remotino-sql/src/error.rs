//! Errors for the SQL backend.

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors produced by the SQL backend.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The database rejected the operation or the connection failed.
    #[error("sql: {0}")]
    Sql(#[from] tiberius::error::Error),

    /// Network or TLS failure reaching the server.
    #[error("connect: {0}")]
    Connect(#[source] std::io::Error),

    /// A stored row could not be turned back into a chain entry.
    ///
    /// Distinct from [`Error::Crypto`] so that "the database gave us something we cannot
    /// parse" is never mistaken for a cryptographic failure - the first is corruption or
    /// a version skew, the second is an attack or a bug.
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
    ///
    /// Refusing to run is deliberate: a client that silently ignored columns it did not
    /// know about could append entries an older peer cannot verify.
    #[error("schema version {found} is newer than supported version {supported}")]
    SchemaTooNew {
        /// Version recorded in the database.
        found: i32,
        /// Highest version this build implements.
        supported: i32,
    },

    /// An identity id already maps to a different public blob.
    ///
    /// A `key_id` is a hash of the keys it names, so this means someone tried to bind an
    /// existing id to keys that do not produce it - either corruption or an attempt to
    /// hijack an id. Never silently overwritten.
    #[error("identity {key_id} already exists with different keys")]
    IdentityConflict {
        /// The conflicting id.
        key_id: remotino_crypto::identity::KeyId,
    },

    /// The schema-migration lock could not be acquired.
    ///
    /// Another client is migrating, or held the lock past the timeout. Retrying is
    /// reasonable; proceeding without it is not, because the migration steps are
    /// check-then-act and would race.
    #[error("could not acquire the schema migration lock")]
    MigrationLock,

    /// The runtime backing the blocking bridge could not be created.
    #[error("runtime: {0}")]
    Runtime(#[source] std::io::Error),
}
