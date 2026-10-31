//! Embedded SQLite repository - the single-seat source of truth (`DESIGN.md` 3).
//!
//! Implements [`remotino_crypto::repository::Repository`] over a local SQLite file. It is
//! the single-seat counterpart to `remotino-sql`'s `SqlRepo`: same trait, same
//! `MemoryRepo` conformance contract, different storage. Nothing above the trait knows
//! which is in use.
//!
//! # Why SQLite and not LocalDB
//!
//! The designed single-seat backend was SQL Server LocalDB, but `tiberius` (what `SqlRepo`
//! speaks) is TCP-only and LocalDB is named-pipe-only - they cannot connect. SQLite is the
//! embedded store our stack can actually talk to, and it is already bundled for the cache.
//! `DESIGN.md` 3 records the full reasoning.
//!
//! # Source of truth vs cache
//!
//! This is not the cache (`remotino-cache`). The cache is an untrusted local *mirror* of a
//! server, re-verified on every load. This is the *authority* in a single-seat deployment:
//! there is no server behind it. Append-only here is **evident, not enforced** - the user
//! owns the file and could edit it - but the signed hash chain still makes tampering
//! detectable, which is the same guarantee LocalDB would have given single-seat.

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

pub mod error;
pub mod store;

pub use error::{Error, Result};
pub use store::SqliteRepo;
