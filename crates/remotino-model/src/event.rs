//! The domain events.
//!
//! One [`Event`] per audit-chain entry. The event's *kind* is the entry's cleartext
//! `action` string (a store reader sees which kinds occurred and when - that is the
//! metadata leak `CRYPTO.md` 1 already discloses), and the event's *body* is the entry
//! payload, which is CBOR-encoded here and, for content, encrypted under a folder key.
//!
//! # What is encrypted and what is not
//!
//! - A folder's **name** and an entry's **connection details** are encrypted under the
//!   folder content key: [`SealedBlob`]. Unreadable without a grant.
//! - An `AclGranted`'s **wrapped key** is a [`WrappedKey`] - already sealed to the
//!   grantee, so safe in the clear.
//! - Ids, parent links, and grantee key-ids are cleartext structure. This is the folder
//!   graph shape, which is not secret (`CRYPTO.md` 1).

use remotino_crypto::envelope::{SealedBlob, WrappedKey};
use remotino_crypto::identity::{KeyId, PublicIdentity};
use serde::{Deserialize, Serialize};

use crate::ids::{CredentialId, EntryId, FolderId};
use crate::{Error, Result};

/// A single change to the connection manager's state.
///
/// `#[non_exhaustive]` so new event kinds can be added without a breaking change - old
/// clients that meet an unknown kind should skip it rather than fail, which the fold does.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Event {
    /// A folder was created. `name` is sealed under the folder's own content key.
    FolderCreated {
        /// The new folder's id.
        id: FolderId,
        /// Parent folder, or `None` for a root.
        parent: Option<FolderId>,
        /// Folder name, sealed under this folder's content key.
        name: SealedBlob,
    },

    /// A folder was renamed. `name` is sealed under the folder's content key.
    FolderRenamed {
        /// Folder to rename.
        id: FolderId,
        /// New name, sealed under the folder's content key.
        name: SealedBlob,
    },

    /// A folder was deleted. Its entries are considered gone with it.
    FolderDeleted {
        /// Folder to delete.
        id: FolderId,
    },

    /// A folder was moved to a new parent (or to the root).
    ///
    /// Only the parent link changes - cleartext structure (`CRYPTO.md` 1) - so no content is
    /// re-sealed. The folder keeps its own content key, name, entries and grants.
    FolderMoved {
        /// Folder to move.
        id: FolderId,
        /// New parent, or `None` for the root.
        new_parent: Option<FolderId>,
    },

    /// A connection entry was created or replaced. `data` is sealed under the folder key.
    EntryUpserted {
        /// Entry id.
        id: EntryId,
        /// Folder it belongs to.
        folder: FolderId,
        /// Connection details, sealed under the folder's content key.
        data: SealedBlob,
    },

    /// A connection entry was removed.
    EntryDeleted {
        /// Entry to remove.
        id: EntryId,
    },

    /// A user was granted read access to a folder: the folder's content key, wrapped to
    /// them.
    AclGranted {
        /// Folder access is granted to.
        folder: FolderId,
        /// The user receiving access.
        grantee: KeyId,
        /// The folder content key, sealed to the grantee.
        wrapped_key: WrappedKey,
    },

    /// A user's access to a folder was revoked.
    ///
    /// Revocation is forward-only (`CRYPTO.md` 6): this records the intent and removes the
    /// grant from the ACL, but a key rotation (a new content key and fresh grants for the
    /// remaining users, expressed as further events) is what actually stops future reads.
    AclRevoked {
        /// Folder access is revoked on.
        folder: FolderId,
        /// The user losing access.
        grantee: KeyId,
    },

    /// A user's personal vault content key, wrapped to them. The vault is "a folder only you
    /// hold the key to" (`DESIGN.md` 4): credentials are sealed under this key, so only the
    /// owner can read them. Emitted once per owner, before their first credential.
    VaultKeyWrapped {
        /// The vault owner.
        owner: KeyId,
        /// The vault content key, sealed to the owner.
        wrapped_key: WrappedKey,
    },

    /// A credential was created or replaced. `data` is the whole credential (name, kind,
    /// username, domain, and the secret) sealed under the credential's own content key -
    /// the key published by [`Event::CredentialGranted`]. (Legacy credentials, from before
    /// per-credential keys, are sealed under the owner's vault key; see
    /// [`Event::VaultKeyWrapped`].)
    CredentialUpserted {
        /// Credential id.
        id: CredentialId,
        /// The sealed credential.
        data: SealedBlob,
    },

    /// A credential was removed.
    CredentialDeleted {
        /// Credential to remove.
        id: CredentialId,
    },

    /// A credential's content key, wrapped to a user. Emitted for the owner when a
    /// credential is created (so they hold its key) and for a grantee when it is shared -
    /// the credential analogue of [`Event::AclGranted`]. A credential is readable by
    /// exactly the users who hold a live grant here.
    CredentialGranted {
        /// Credential the key belongs to.
        credential: CredentialId,
        /// The user receiving access.
        grantee: KeyId,
        /// The credential content key, sealed to the grantee.
        wrapped_key: WrappedKey,
    },

    /// A user's access to a shared credential was revoked. Forward-only, exactly as
    /// [`Event::AclRevoked`]: it removes the grant so no *new* reads succeed, but does not
    /// claw back a key the user already cached.
    CredentialRevoked {
        /// Credential access is revoked on.
        credential: CredentialId,
        /// The user losing access.
        grantee: KeyId,
    },

    /// A user was enrolled into this repository: their public identity, published so others
    /// can grant them folder access (a grant wraps a content key to their public key). The
    /// `name` is a human label the enroller chose. Re-enrolling the same key updates it.
    UserEnrolled {
        /// A human-readable label for the user.
        name: String,
        /// The user's public identity (public keys + key id).
        identity: PublicIdentity,
    },
}

impl Event {
    /// The cleartext action string for this event, stored as the entry's `action`.
    ///
    /// This is what a store reader sees, so it names the *kind* of change but nothing
    /// about its content.
    #[must_use]
    pub fn action(&self) -> &'static str {
        match self {
            Event::FolderCreated { .. } => "FolderCreated",
            Event::FolderRenamed { .. } => "FolderRenamed",
            Event::FolderDeleted { .. } => "FolderDeleted",
            Event::FolderMoved { .. } => "FolderMoved",
            Event::EntryUpserted { .. } => "EntryUpserted",
            Event::EntryDeleted { .. } => "EntryDeleted",
            Event::AclGranted { .. } => "AclGranted",
            Event::AclRevoked { .. } => "AclRevoked",
            Event::VaultKeyWrapped { .. } => "VaultKeyWrapped",
            Event::CredentialUpserted { .. } => "CredentialUpserted",
            Event::CredentialDeleted { .. } => "CredentialDeleted",
            Event::CredentialGranted { .. } => "CredentialGranted",
            Event::CredentialRevoked { .. } => "CredentialRevoked",
            Event::UserEnrolled { .. } => "UserEnrolled",
        }
    }

    /// Encodes this event as the CBOR bytes that become an entry payload.
    ///
    /// # Errors
    ///
    /// [`Error::Encoding`] if encoding fails.
    pub fn to_payload(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).map_err(|_| Error::Encoding("event encode"))?;
        Ok(buf)
    }

    /// Decodes an event from an entry payload.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if the payload is not a valid event.
    pub fn from_payload(bytes: &[u8]) -> Result<Self> {
        ciborium::from_reader(bytes).map_err(|_| Error::Malformed("event decode"))
    }
}
