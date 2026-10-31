//! Local SQLite cache of the audit chain (`DESIGN.md` 3).
//!
//! # Why this exists
//!
//! The performance budget is a cold start under 500 ms with a thousand entries
//! (`DESIGN.md` 2), and the way that is met is: **render from a local cache immediately,
//! then read only what is new from the server.** Startup must never block on an SMB or
//! SQL round trip. This crate is that cache.
//!
//! # What it stores, and what it does NOT trust
//!
//! It holds entries that have **already been verified** by
//! [`remotino_crypto::chain::verify_chain`], plus the pinned [`Head`] and the sync
//! cursor. The cache is on the local disk of a machine whose user is not necessarily an
//! administrator, so it is treated as **untrusted persistence, not a trusted source**:
//!
//! - Entries are decoded through [`Entry::from_bytes`], so a cache file someone tampered
//!   with cannot inject a non-canonical alias.
//! - On load, the whole cached chain is re-verified before it is believed. A cache is a
//!   speed optimisation; it never becomes a way to bypass verification.
//!
//! That second point is the one that is easy to get wrong. A cache that was trusted
//! blindly would be a place to smuggle forged history onto a client that had already done
//! its careful verification against the server. So the rule is simple: **cache the result
//! of verification, re-verify on load, and treat a mismatch as "throw the cache away and
//! resync", never as an error to the user.**
//!
//! # Relationship to the server
//!
//! The server (`remotino-sql`) is the source of truth. The cache mirrors a prefix of it.
//! The sync flow is:
//!
//! 1. Load the cache, re-verify, render. Fast, offline-capable.
//! 2. Ask the server for its [`Head`]. If it matches the cache, done.
//! 3. Otherwise read entries after the cursor, verify them as a continuation of the
//!    pinned head, append to the cache, advance the cursor.
//!
//! This crate owns steps 1 and 3's storage; the caller orchestrates, because only it
//! holds the server connection and the identity directory.

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

pub mod cache;
pub mod error;

pub use cache::Cache;
pub use error::{Error, Result};
