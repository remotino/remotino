//! The Remotino domain model: events, the fold, and the decrypted projection.
//!
//! The audit chain (`remotino-crypto`) stores signed, ordered entries. This crate is what
//! those entries *mean*: each entry payload is one [`Event`], and the current state of the
//! connection manager - folders, connection entries, who-can-see-what - is the fold of
//! every event (`DESIGN.md` 3, "the log is the database").
//!
//! # Two layers, split on the crypto boundary
//!
//! The fold is deliberately in two stages, because they have very different testability
//! and trust properties:
//!
//! 1. [`structure`] - a pure, crypto-free fold of events into a [`structure::Structure`]:
//!    the folder graph, the ACL table, and the still-encrypted blobs. Deterministic, and
//!    testable with no keys at all. This is where the *shape* of the data lives - which is
//!    exactly the metadata a store reader can already see (`CRYPTO.md` 1), so keeping it
//!    key-free is honest about what is and is not protected.
//!
//! 2. [`projection`] - given a [`structure::Structure`] and *your* [`Identity`], unwraps
//!    the content keys you were granted and decrypts the folders and entries you can
//!    actually read. Folders you have no key for remain visible as nodes but opaque as
//!    content - you cannot read what was never wrapped to you, which is the whole access
//!    model (`CRYPTO.md` 5).
//!
//! [`Identity`]: remotino_crypto::identity::Identity
//!
//! # Why events carry their own crypto
//!
//! An `AclGranted` event carries a [`remotino_crypto::envelope::WrappedKey`] - a content
//! key already sealed to the grantee. It is safe in the clear because it is encrypted to
//! the recipient. An `EntryUpserted` carries a [`remotino_crypto::envelope::SealedBlob`]
//! encrypted under the folder's content key. So the structural fold can move these blobs
//! around without holding any key, and only the projection - which holds an identity -
//! turns them into plaintext.

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
pub mod event;
pub mod ids;
pub mod projection;
pub mod structure;

pub use error::{Error, Result};
pub use event::Event;
pub use ids::{EntryId, FolderId};
pub use projection::{Connection, ConnectionKind, Projection};
pub use structure::Structure;
