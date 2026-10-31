//! Connection configuration for the Postgres backend.
//!
//! Deliberately narrow, mirroring the SQL Server config: a host, a database, and a login.
//! No shared application login exists as a variant - a per-user login sits in every client's
//! config and any user could extract it, discarding the least-privilege guarantee.

/// Whether the connection uses TLS, and if so which server certificate is trusted.
///
/// The trust model is trust-on-first-use, not the web PKI: a shared repository is typically a
/// LAN host with a self-signed certificate, so we pin the exact certificate (by SHA-256)
/// rather than chaining to a public CA. See [`crate::tls`].
#[derive(Debug, Clone, Default)]
pub enum PgTls {
    /// No TLS. Loopback and throwaway-container use only.
    #[default]
    Disable,
    /// Require TLS and pin the server certificate by its SHA-256 fingerprint.
    /// `pinned_sha256` is `None` until the user has approved a fingerprint, at which point a
    /// connect can only succeed against that exact certificate.
    Require {
        /// The approved certificate fingerprint, or `None` if not yet trusted.
        pinned_sha256: Option<[u8; 32]>,
    },
}

/// Where and how to connect.
#[derive(Debug, Clone)]
pub struct PgConfig {
    /// Host name or address.
    pub host: String,
    /// TCP port (Postgres default is 5432).
    pub port: u16,
    /// Database name.
    pub database: String,
    /// Role/login name.
    pub user: String,
    /// Password for `user`, expected to have been unsealed from the caller's identity moments
    /// before and dropped after connecting - never persisted by this crate.
    pub password: String,
    /// TLS mode and pinned certificate.
    pub tls: PgTls,
}

impl PgConfig {
    /// A local development configuration against a plaintext Postgres on loopback.
    ///
    /// For pointing at a throwaway container. Not for anything else - there is no TLS here.
    #[must_use]
    pub fn local_dev(database: &str, user: &str, password: &str) -> Self {
        Self {
            host: "localhost".to_owned(),
            port: 5432,
            database: database.to_owned(),
            user: user.to_owned(),
            password: password.to_owned(),
            tls: PgTls::Disable,
        }
    }

    /// Builds a `tokio_postgres` config against `database` (which may differ from
    /// [`PgConfig::database`], e.g. the `postgres` maintenance db for CREATE/DROP DATABASE).
    pub(crate) fn to_pg(&self, database: &str) -> tokio_postgres::Config {
        let mut cfg = tokio_postgres::Config::new();
        cfg.host(&self.host)
            .port(self.port)
            .user(&self.user)
            .password(&self.password)
            .dbname(database);
        if matches!(self.tls, PgTls::Require { .. }) {
            cfg.ssl_mode(tokio_postgres::config::SslMode::Require);
        }
        cfg
    }
}

/// Rejects an identifier that is not `[A-Za-z0-9_]` (and non-empty, length-capped), so it can
/// be safely interpolated into DDL that cannot be parameterised (database and role names).
pub(crate) fn validate_identifier(name: &str) -> crate::Result<&str> {
    let ok = !name.is_empty()
        && name.len() <= 63
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        // A leading digit is not a valid unquoted identifier and hints at something odd.
        && !name.as_bytes().first().is_some_and(u8::is_ascii_digit);
    if ok {
        Ok(name)
    } else {
        Err(crate::Error::BadIdentifier(name.to_owned()))
    }
}
