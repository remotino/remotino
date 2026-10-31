//! The decrypted projection: what *this* identity can actually read.
//!
//! Given a [`Structure`] and an [`Identity`], this unwraps the folder content keys the
//! identity was granted and decrypts the folder names and connection entries it can read.
//! It is the bridge from "the shape of everyone's data" to "the connection tree I see".
//!
//! The access model lives here as a plain consequence of the crypto: a folder is readable
//! iff its content key was wrapped to this identity ([`Structure::grant_for`]). A folder
//! with no grant for me stays in the tree as an opaque node - I can see it exists, because
//! that shape is not secret, but I cannot read its name or its entries, because they were
//! never encrypted to me (`CRYPTO.md` 5). There is no flag to flip; the plaintext simply
//! is not derivable.

use std::collections::HashMap;

use remotino_crypto::envelope::ContentKey;
use remotino_crypto::identity::Identity;
use serde::{Deserialize, Serialize};

use crate::ids::{CredentialId, EntryId, FolderId};
use crate::structure::Structure;
use crate::Result;

/// The kind of a connection entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ConnectionKind {
    /// An RDP connection.
    Rdp,
    /// An SSH connection.
    Ssh,
}

/// A decrypted connection entry - the plaintext connection details.
///
/// The credential fields are deliberately absent: connection *definitions* live in shared
/// folders, but credentials live in a user's personal vault, sealed separately
/// (`DESIGN.md` 4). This is the shareable half.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    /// RDP or SSH.
    pub kind: ConnectionKind,
    /// Display name.
    pub name: String,
    /// Host or address.
    pub host: String,
    /// Port.
    pub port: u16,
    /// Optional reference to a credential in the user's vault, by opaque id.
    ///
    /// A reference, not a secret: the credential itself is never in a shared folder.
    pub credential_ref: Option<String>,
}

/// How a credential authenticates. The secret never leaves the backend process - the UI
/// only ever sees the surrounding metadata (name, username, fingerprint).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CredentialSecret {
    /// A password.
    Password {
        /// The password.
        password: String,
    },
    /// A private key in OpenSSH format, an optional passphrase, and the public-key
    /// fingerprint (`SHA256:…`) kept for display so the key need not be re-parsed.
    Key {
        /// OpenSSH private key text.
        private_key: String,
        /// Optional passphrase protecting the key.
        passphrase: Option<String>,
        /// Public-key fingerprint, for telling keys apart at a glance.
        fingerprint: String,
    },
}

/// A decrypted vault credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    /// Display name (renamable).
    pub name: String,
    /// RDP or SSH - drives the icon and the username format.
    pub kind: ConnectionKind,
    /// Login username.
    pub username: String,
    /// Optional domain (RDP shows `DOMAIN\username`).
    pub domain: Option<String>,
    /// Password or key.
    pub secret: CredentialSecret,
}

/// A folder as this identity sees it after projection.
#[derive(Debug, Clone)]
pub struct VisibleFolder {
    /// Parent folder.
    pub parent: Option<FolderId>,
    /// The decrypted name, or `None` if this identity holds no grant.
    ///
    /// `None` means the folder is visible as structure but its content is not readable -
    /// the honest representation of "you know this exists but cannot open it".
    pub name: Option<String>,
    /// Whether this identity can read the folder's contents.
    pub readable: bool,
}

/// The connection tree as it appears to one identity.
#[derive(Debug, Clone, Default)]
pub struct Projection {
    /// Folders by id, each annotated with whether this identity can read it.
    pub folders: HashMap<FolderId, VisibleFolder>,
    /// Decrypted connections, by entry id. Only entries in readable folders appear.
    pub connections: HashMap<EntryId, Connection>,
    /// Decrypted personal vault credentials, by id. Only this identity's own vault.
    pub credentials: HashMap<CredentialId, Credential>,
}

impl Projection {
    /// Projects a structure through an identity, decrypting what the identity can read.
    ///
    /// Never fails on an *unreadable* folder - that is the normal case for folders not
    /// shared with this identity, and it yields a folder with `name: None` rather than an
    /// error. It only errors if a folder this identity *was* granted cannot be decrypted,
    /// which would mean the grant and the sealed content disagree - a real inconsistency.
    ///
    /// # Errors
    ///
    /// [`Error::Crypto`] if a granted folder's key unwraps but its name or an entry then
    /// fails to decrypt.
    ///
    /// [`Error::Crypto`]: crate::Error::Crypto
    pub fn project(structure: &Structure, identity: &Identity) -> Result<Self> {
        let mut projection = Self::default();

        // Unwrap the content key for every folder this identity was granted. A folder can
        // appear with no grant (opaque) or with a grant (readable).
        let mut folder_keys: HashMap<FolderId, ContentKey> = HashMap::new();
        for (&folder_id, node) in &structure.folders {
            let readable = if let Some(wrapped) = structure.grant_for(folder_id, &identity.key_id())
            {
                let key = ContentKey::unwrap_for(wrapped, identity)?;
                let name = decrypt_name(&key, folder_id, node)?;
                folder_keys.insert(folder_id, key);
                projection.folders.insert(
                    folder_id,
                    VisibleFolder {
                        parent: node.parent,
                        name: Some(name),
                        readable: true,
                    },
                );
                true
            } else {
                projection.folders.insert(
                    folder_id,
                    VisibleFolder {
                        parent: node.parent,
                        name: None,
                        readable: false,
                    },
                );
                false
            };
            let _ = readable;
        }

        // Decrypt entries whose folder this identity can read. Entries in opaque folders
        // are skipped: their bytes are present but their key is not held.
        for (&entry_id, node) in &structure.entries {
            if let Some(key) = folder_keys.get(&node.folder) {
                let plaintext = key
                    .open(&node.sealed_data, entry_id.0.as_slice())
                    .map_err(crate::Error::Crypto)?;
                let connection: Connection = ciborium::from_reader(plaintext.as_slice())
                    .map_err(|_| crate::Error::Malformed("connection decode"))?;
                projection.connections.insert(entry_id, connection);
            }
        }

        // Decrypt every credential this identity can read. A credential is readable either
        // through a per-credential grant (the shareable model) or, for a legacy credential,
        // through this identity's own vault key.
        let me = identity.key_id();
        // The legacy vault key, unwrapped once if this identity owns a vault.
        let legacy_vault_key = structure
            .vault_grants
            .get(&me)
            .and_then(|wrapped| ContentKey::unwrap_for(wrapped, identity).ok());

        for (&cred_id, sealed) in &structure.credentials {
            if let Some(wrapped) = structure.credential_grant_for(cred_id, &me) {
                // A grant addressed to me must unwrap and open; a failure means the grant and
                // the sealed content disagree - a real inconsistency, so propagate it.
                let key = ContentKey::unwrap_for(wrapped, identity)?;
                let plaintext = key
                    .open(sealed, cred_id.0.as_slice())
                    .map_err(crate::Error::Crypto)?;
                projection
                    .credentials
                    .insert(cred_id, decode_credential(&plaintext)?);
            } else if let Some(vault_key) = &legacy_vault_key {
                // Legacy credential sealed under a vault key. It is mine only if my vault key
                // opens it; another user's credential in the same shared repository simply
                // will not, and is skipped rather than erroring.
                if let Ok(plaintext) = vault_key.open(sealed, cred_id.0.as_slice()) {
                    projection
                        .credentials
                        .insert(cred_id, decode_credential(&plaintext)?);
                }
            }
        }

        Ok(projection)
    }
}

fn decode_credential(plaintext: &[u8]) -> Result<Credential> {
    ciborium::from_reader(plaintext).map_err(|_| crate::Error::Malformed("credential decode"))
}

fn decrypt_name(
    key: &ContentKey,
    folder_id: FolderId,
    node: &crate::structure::FolderNode,
) -> Result<String> {
    // The folder id is the AAD, binding the sealed name to this specific folder so a name
    // blob cannot be moved to a different folder and still decrypt.
    let plaintext = key
        .open(&node.sealed_name, folder_id.0.as_slice())
        .map_err(crate::Error::Crypto)?;
    String::from_utf8(plaintext.to_vec()).map_err(|_| crate::Error::Malformed("folder name utf8"))
}

/// Helpers for producing the sealed events a caller appends. Kept beside the projection so
/// the seal side and the open side of each blob are defined together and cannot drift
/// apart on their AAD.
pub mod build {
    use super::{Connection, Credential, FolderId};
    use remotino_crypto::envelope::{ContentKey, SealedBlob};
    use crate::ids::CredentialId;
    use crate::{Error, Result};

    /// Seals a credential under the owner's vault key, bound to the credential id.
    ///
    /// # Errors
    ///
    /// [`Error::Encoding`] or [`Error::Crypto`].
    pub fn seal_credential(
        vault_key: &ContentKey,
        id: CredentialId,
        credential: &Credential,
    ) -> Result<SealedBlob> {
        let mut buf = Vec::new();
        ciborium::into_writer(credential, &mut buf)
            .map_err(|_| Error::Encoding("credential encode"))?;
        vault_key.seal(&buf, id.0.as_slice()).map_err(Error::Crypto)
    }

    /// Seals a folder name under its content key, bound to the folder id.
    ///
    /// # Errors
    ///
    /// [`Error::Crypto`] on an AEAD failure.
    pub fn seal_folder_name(key: &ContentKey, folder: FolderId, name: &str) -> Result<SealedBlob> {
        key.seal(name.as_bytes(), folder.0.as_slice())
            .map_err(Error::Crypto)
    }

    /// Seals a connection under a folder content key, bound to the entry id.
    ///
    /// # Errors
    ///
    /// [`Error::Encoding`] or [`Error::Crypto`].
    pub fn seal_connection(
        key: &ContentKey,
        entry: crate::ids::EntryId,
        connection: &Connection,
    ) -> Result<SealedBlob> {
        let mut buf = Vec::new();
        ciborium::into_writer(connection, &mut buf)
            .map_err(|_| Error::Encoding("connection encode"))?;
        key.seal(&buf, entry.0.as_slice()).map_err(Error::Crypto)
    }
}

#[cfg(test)]
mod tests {
    use super::build::{seal_connection, seal_credential, seal_folder_name};
    use super::*;
    use crate::event::Event;
    use crate::ids::CredentialId;
    use remotino_crypto::envelope::ContentKey;
    use remotino_crypto::identity::Identity;

    #[test]
    fn a_vault_credential_decrypts_only_for_its_owner() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let vault_key = ContentKey::generate().unwrap();
        let id = CredentialId::generate().unwrap();
        let cred = Credential {
            name: "prod root".to_owned(),
            kind: ConnectionKind::Ssh,
            username: "root".to_owned(),
            domain: None,
            secret: CredentialSecret::Password { password: "hunter2".to_owned() },
        };
        let events = vec![
            Event::VaultKeyWrapped {
                owner: alice.key_id(),
                wrapped_key: vault_key.wrap_to(alice.public()).unwrap(),
            },
            Event::CredentialUpserted {
                id,
                data: seal_credential(&vault_key, id, &cred).unwrap(),
            },
        ];
        let s = Structure::fold(&events).unwrap();

        let mine = Projection::project(&s, &alice).unwrap();
        assert_eq!(mine.credentials.len(), 1);
        assert_eq!(mine.credentials[&id].username, "root");

        // Bob holds no vault key for this vault, so he sees none of it.
        let theirs = Projection::project(&s, &bob).unwrap();
        assert!(theirs.credentials.is_empty());
    }

    #[test]
    fn a_shared_credential_decrypts_for_the_grantee_only() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let mallory = Identity::generate().unwrap();
        // Per-credential key model: the credential is sealed under its own key, wrapped to
        // the owner and to a grantee.
        let cred_key = ContentKey::generate().unwrap();
        let id = CredentialId::generate().unwrap();
        let cred = Credential {
            name: "shared admin".to_owned(),
            kind: ConnectionKind::Rdp,
            username: "administrator".to_owned(),
            domain: Some("CORP".to_owned()),
            secret: CredentialSecret::Password { password: "s3cret".to_owned() },
        };
        let events = vec![
            Event::CredentialUpserted { id, data: seal_credential(&cred_key, id, &cred).unwrap() },
            Event::CredentialGranted {
                credential: id,
                grantee: alice.key_id(),
                wrapped_key: cred_key.wrap_to(alice.public()).unwrap(),
            },
            Event::CredentialGranted {
                credential: id,
                grantee: bob.key_id(),
                wrapped_key: cred_key.wrap_to(bob.public()).unwrap(),
            },
        ];
        let s = Structure::fold(&events).unwrap();

        // Owner and grantee both read it.
        assert_eq!(Projection::project(&s, &alice).unwrap().credentials[&id].username, "administrator");
        assert_eq!(Projection::project(&s, &bob).unwrap().credentials[&id].username, "administrator");
        // Nobody else can - no grant, no key.
        assert!(Projection::project(&s, &mallory).unwrap().credentials.is_empty());

        // Revoking Bob removes his access (forward-only, at the structural level).
        let mut s2 = s.clone();
        s2.apply(&Event::CredentialRevoked { credential: id, grantee: bob.key_id() }).unwrap();
        assert!(Projection::project(&s2, &bob).unwrap().credentials.is_empty());
        assert!(Projection::project(&s2, &alice).unwrap().credentials.contains_key(&id));
    }

    fn connection(name: &str) -> Connection {
        Connection {
            kind: ConnectionKind::Rdp,
            name: name.to_owned(),
            host: "192.0.2.10".to_owned(),
            port: 3389,
            credential_ref: None,
        }
    }

    /// Builds a small world: one folder Alice is granted, one she is not, each with an
    /// entry. Returns the events plus the folder ids.
    fn world(alice: &Identity, bob: &Identity) -> (Vec<Event>, FolderId, FolderId) {
        let shared = FolderId::generate().unwrap();
        let secret = FolderId::generate().unwrap();
        let shared_key = ContentKey::generate().unwrap();
        let secret_key = ContentKey::generate().unwrap();
        let e1 = EntryId::generate().unwrap();
        let e2 = EntryId::generate().unwrap();

        let events = vec![
            Event::FolderCreated {
                id: shared,
                parent: None,
                name: seal_folder_name(&shared_key, shared, "Shared").unwrap(),
            },
            Event::AclGranted {
                folder: shared,
                grantee: alice.key_id(),
                wrapped_key: shared_key.wrap_to(alice.public()).unwrap(),
            },
            Event::EntryUpserted {
                id: e1,
                folder: shared,
                data: seal_connection(&shared_key, e1, &connection("db01")).unwrap(),
            },
            Event::FolderCreated {
                id: secret,
                parent: None,
                name: seal_folder_name(&secret_key, secret, "Bob only").unwrap(),
            },
            Event::AclGranted {
                folder: secret,
                grantee: bob.key_id(),
                wrapped_key: secret_key.wrap_to(bob.public()).unwrap(),
            },
            Event::EntryUpserted {
                id: e2,
                folder: secret,
                data: seal_connection(&secret_key, e2, &connection("bob-only")).unwrap(),
            },
        ];
        (events, shared, secret)
    }

    #[test]
    fn i_can_read_a_folder_granted_to_me() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let (events, shared, _secret) = world(&alice, &bob);

        let structure = Structure::fold(&events).unwrap();
        let p = Projection::project(&structure, &alice).unwrap();

        let folder = &p.folders[&shared];
        assert!(folder.readable);
        assert_eq!(folder.name.as_deref(), Some("Shared"));
        assert_eq!(p.connections.len(), 1);
        assert!(p.connections.values().any(|c| c.name == "db01"));
    }

    #[test]
    fn a_folder_not_granted_to_me_is_opaque_but_visible() {
        // The whole access model: I see the folder exists (structure is not secret) but
        // cannot read its name or entries (content was never wrapped to me).
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let (events, _shared, secret) = world(&alice, &bob);

        let structure = Structure::fold(&events).unwrap();
        let p = Projection::project(&structure, &alice).unwrap();

        let folder = &p.folders[&secret];
        assert!(!folder.readable, "Alice must not read Bob's folder");
        assert_eq!(folder.name, None);
        // Bob's entry is not in Alice's connection list at all.
        assert!(p.connections.values().all(|c| c.name != "bob-only"));
    }

    #[test]
    fn bob_sees_the_mirror_image() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let (events, shared, secret) = world(&alice, &bob);

        let structure = Structure::fold(&events).unwrap();
        let p = Projection::project(&structure, &bob).unwrap();

        assert!(!p.folders[&shared].readable);
        assert!(p.folders[&secret].readable);
        assert_eq!(p.folders[&secret].name.as_deref(), Some("Bob only"));
    }

    #[test]
    fn revocation_removes_readability_at_the_structural_level() {
        // After revoke (without rotation) the grant is gone, so the projection can no
        // longer unwrap the key - forward-only revocation, as the model documents.
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let (mut events, shared, _secret) = world(&alice, &bob);
        events.push(Event::AclRevoked {
            folder: shared,
            grantee: alice.key_id(),
        });

        let structure = Structure::fold(&events).unwrap();
        let p = Projection::project(&structure, &alice).unwrap();
        assert!(!p.folders[&shared].readable);
    }
}
