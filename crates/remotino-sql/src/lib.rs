//! SQL Server backend for Remotino (`DESIGN.md` 3, Phase 2).
//!
//! Implements [`remotino_crypto::repository::Repository`] against SQL Server. This is the
//! only production backend: `DESIGN.md` 3 records why the file backend was dropped, but
//! the short version is that `DENY UPDATE, DELETE` turns append-only from a convention
//! clients follow into a constraint they cannot violate.
//!
//! # Two deployment shapes, one implementation
//!
//! | | Single seat | Shared |
//! |---|---|---|
//! | Engine | LocalDB | SQL Server Express or higher |
//! | Auth | the local user | per-user SQL Authentication |
//! | Append-only | *evident* - the user is sysadmin on their own instance | *enforced* |
//!
//! Nothing here differs between them except the connection string. The asymmetry in the
//! last row is real and documented in `DESIGN.md`: on LocalDB the user could drop the
//! `DENY`, which is acceptable only because a single-seat deployment has no one else to
//! protect the log from.
//!
//! # The store is untrusted
//!
//! This crate moves opaque bytes. It never sees plaintext, and its structural checks are
//! hygiene, not a security boundary - a client must still run
//! [`remotino_crypto::chain::verify_chain`] over whatever it reads. That is stated on the
//! `Repository` trait itself and repeated here because a backend is exactly where someone
//! is tempted to start trusting the database.
//!
//! # Blocking, and why
//!
//! `Repository` is synchronous so the crypto core stays free of an executor dependency.
//! `tiberius` is async, so [`SqlRepo`] owns a current-thread Tokio runtime and blocks on
//! it.
//!
//! **Consequence: do not call [`SqlRepo`] from inside an async context.** Tokio panics if
//! `block_on` runs on a thread already driving a runtime. In Tauri this means using a
//! non-async command, or `spawn_blocking`. If that constraint ever becomes awkward, the
//! fix is an async twin of the trait rather than sprinkling `spawn_blocking` at call
//! sites - see the note in `DESIGN.md` 3.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
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

pub mod config;
pub mod directory;
pub mod error;
pub mod provision;
pub mod repo;
pub mod schema;

pub use config::{Auth, SqlConfig};
pub use directory::SealedVault;
pub use error::{Error, Result};
pub use provision::{provision_login, ProvisionedLogin};
pub use repo::{check_privileges, drop_database, ensure_database, Privileges};
pub use repo::SqlRepo;
