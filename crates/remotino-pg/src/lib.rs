//! Postgres backend for Remotino: an append-only chain store over Postgres.
//!
//! The Postgres sibling of `remotino-sql`. It implements
//! [`remotino_crypto::repository::Repository`] against Postgres and adds the admin
//! operations (create/drop database, migrate, privilege check) the setup flow needs.
//!
//! # Append-only, two ways
//!
//! Ordinary `remotino_user` logins get only `SELECT`/`INSERT` on `events`, and a statement
//! trigger raises on any `UPDATE`/`DELETE`/`TRUNCATE` - so the log cannot be rewritten in
//! place even by the table owner. Combined with the signed hash chain the client verifies,
//! tampering is both blocked and detectable.
//!
//! # The store is untrusted
//!
//! This crate moves opaque bytes and never sees plaintext. Its structural checks are hygiene,
//! not a security boundary: a client must still run
//! [`remotino_crypto::chain::verify_chain`] over whatever it reads.
//!
//! # Blocking
//!
//! `Repository` is synchronous, so [`PgRepo`] owns a current-thread Tokio runtime and blocks
//! on it. **Do not call it from inside an async context** - `block_on` panics on a thread
//! already driving a runtime; use a dedicated thread (as the app's `ThreadedRepo` does).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod config;
pub mod error;
pub mod provision;
pub mod repo;
pub mod schema;
pub mod tls;

pub use config::{PgConfig, PgTls};
pub use error::{Error, Result};
pub use provision::{provision_login, ProvisionedLogin};
pub use repo::{drop_database, ensure_database, PgRepo};
pub use tls::{probe_certificate, CertInfo};
