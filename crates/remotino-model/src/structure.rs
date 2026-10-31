//! The crypto-free structural fold.
//!
//! Folds a sequence of [`Event`]s into the *shape* of the data: which folders exist, how
//! they nest, which entries live where, and who has been granted which folder key. It
//! holds the still-encrypted blobs but never decrypts them, so it needs no identity and
//! is fully deterministic - the same events always produce the same structure.
//!
//! Everything here is metadata a store reader can already infer (`CRYPTO.md` 1). Keeping
//! it in a key-free layer is a way of being precise about that: the structure is not
//! secret, the content is, and the two are separated in the type system.

use std::collections::HashMap;

use remotino_crypto::envelope::{SealedBlob, WrappedKey};
use remotino_crypto::identity::{KeyId, PublicIdentity};

use crate::event::Event;
use crate::ids::{CredentialId, EntryId, FolderId};
use crate::{Error, Result};

/// A folder as the structural fold knows it: its place in the graph and its sealed name.
#[derive(Debug, Clone)]
pub struct FolderNode {
    /// Parent, or `None` for a root.
    pub parent: Option<FolderId>,
    /// The folder name, still sealed under the folder content key.
    pub sealed_name: SealedBlob,
}

/// A connection entry as the structural fold knows it: its folder and its sealed data.
#[derive(Debug, Clone)]
pub struct EntryNode {
    /// Folder this entry belongs to.
    pub folder: FolderId,
    /// Connection details, still sealed under the folder content key.
    pub sealed_data: SealedBlob,
}

/// The structural state: the fold of all events, with content left encrypted.
#[derive(Debug, Clone, Default)]
pub struct Structure {
    /// Folders by id.
    pub folders: HashMap<FolderId, FolderNode>,
    /// Entries by id.
    pub entries: HashMap<EntryId, EntryNode>,
    /// For each folder, the content key wrapped to each currently-granted user.
    ///
    /// This is the ACL: a user appears here for a folder exactly when they hold a live
    /// grant. Revocation removes them; a later rotation re-grants the remaining users
    /// under a fresh key. The *values* are wraps only that user can open.
    pub grants: HashMap<FolderId, HashMap<KeyId, WrappedKey>>,

    /// Each user's personal vault content key, wrapped to them. Only the owner can open
    /// their own wrap, so this is the whole vault access model.
    pub vault_grants: HashMap<KeyId, WrappedKey>,

    /// Credentials by id, still sealed under their content key (or, for legacy credentials,
    /// their owner's vault key).
    pub credentials: HashMap<CredentialId, SealedBlob>,

    /// For each credential, its content key wrapped to each currently-granted user. The
    /// credential ACL, mirroring [`Structure::grants`] for folders: a user appears here for
    /// a credential exactly when they hold a live grant on it. Legacy credentials (sealed
    /// under a vault key) have no entry here.
    pub credential_grants: HashMap<CredentialId, HashMap<KeyId, WrappedKey>>,

    /// Users enrolled in this repository, by key id: the public identity to wrap grants to,
    /// and the label chosen for them.
    pub enrolled: HashMap<KeyId, EnrolledUser>,
}

/// An enrolled user, as the fold knows them.
#[derive(Debug, Clone)]
pub struct EnrolledUser {
    /// Human-readable label.
    pub name: String,
    /// Public identity - the keys a grant is wrapped to.
    pub identity: PublicIdentity,
}

impl Structure {
    /// An empty structure.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Folds one event into the structure.
    ///
    /// Unknown event kinds (a `#[non_exhaustive]` addition an older client does not know)
    /// are skipped rather than erroring, so a newer log stays partially readable. Known
    /// events that reference missing folders or entries *do* error, because after chain
    /// verification that is a real inconsistency, not forward-compatibility.
    ///
    /// # Errors
    ///
    /// [`Error::DanglingReference`] if an event references a folder or entry that does not
    /// exist yet.
    pub fn apply(&mut self, event: &Event) -> Result<()> {
        match event {
            Event::FolderCreated { id, parent, name } => {
                if let Some(parent) = parent
                    && !self.folders.contains_key(parent)
                {
                    return Err(Error::DanglingReference("parent folder"));
                }
                self.folders.insert(
                    *id,
                    FolderNode {
                        parent: *parent,
                        sealed_name: name.clone(),
                    },
                );
            }

            Event::FolderRenamed { id, name } => {
                let node = self
                    .folders
                    .get_mut(id)
                    .ok_or(Error::DanglingReference("folder"))?;
                node.sealed_name = name.clone();
            }

            Event::FolderDeleted { id } => {
                self.folders.remove(id);
                self.grants.remove(id);
                // Entries in the deleted folder go with it. Retaining them would leave
                // orphans the projection could never place in the tree.
                self.entries.retain(|_, e| e.folder != *id);
            }

            Event::FolderMoved { id, new_parent } => {
                if !self.folders.contains_key(id) {
                    return Err(Error::DanglingReference("folder to move"));
                }
                if let Some(parent) = new_parent {
                    if !self.folders.contains_key(parent) {
                        return Err(Error::DanglingReference("new parent folder"));
                    }
                    // Refuse to move a folder under itself or one of its descendants, which
                    // would create a cycle the tree walk could never terminate on.
                    if self.is_descendant_or_self(*parent, *id) {
                        return Err(Error::DanglingReference("move would create a folder cycle"));
                    }
                }
                if let Some(node) = self.folders.get_mut(id) {
                    node.parent = *new_parent;
                }
            }

            Event::EntryUpserted { id, folder, data } => {
                if !self.folders.contains_key(folder) {
                    return Err(Error::DanglingReference("folder for entry"));
                }
                self.entries.insert(
                    *id,
                    EntryNode {
                        folder: *folder,
                        sealed_data: data.clone(),
                    },
                );
            }

            Event::EntryDeleted { id } => {
                self.entries.remove(id);
            }

            Event::AclGranted {
                folder,
                grantee,
                wrapped_key,
            } => {
                if !self.folders.contains_key(folder) {
                    return Err(Error::DanglingReference("folder for grant"));
                }
                self.grants
                    .entry(*folder)
                    .or_default()
                    .insert(*grantee, wrapped_key.clone());
            }

            Event::AclRevoked { folder, grantee } => {
                if let Some(folder_grants) = self.grants.get_mut(folder) {
                    folder_grants.remove(grantee);
                }
            }

            Event::VaultKeyWrapped { owner, wrapped_key } => {
                self.vault_grants.insert(*owner, wrapped_key.clone());
            }

            Event::CredentialUpserted { id, data } => {
                self.credentials.insert(*id, data.clone());
            }

            Event::CredentialDeleted { id } => {
                self.credentials.remove(id);
                self.credential_grants.remove(id);
            }

            Event::CredentialGranted {
                credential,
                grantee,
                wrapped_key,
            } => {
                self.credential_grants
                    .entry(*credential)
                    .or_default()
                    .insert(*grantee, wrapped_key.clone());
            }

            Event::CredentialRevoked { credential, grantee } => {
                if let Some(grants) = self.credential_grants.get_mut(credential) {
                    grants.remove(grantee);
                }
            }

            Event::UserEnrolled { name, identity } => {
                self.enrolled.insert(
                    identity.key_id(),
                    EnrolledUser {
                        name: name.clone(),
                        identity: identity.clone(),
                    },
                );
            }
        }
        Ok(())
    }

    /// Folds a whole sequence of events.
    ///
    /// # Errors
    ///
    /// The first [`Error::DanglingReference`] any event produces.
    pub fn fold<'a, I>(events: I) -> Result<Self>
    where
        I: IntoIterator<Item = &'a Event>,
    {
        let mut state = Self::new();
        for event in events {
            state.apply(event)?;
        }
        Ok(state)
    }

    /// The wrap of a folder's content key addressed to `user`, if they hold a grant.
    #[must_use]
    pub fn grant_for(&self, folder: FolderId, user: &KeyId) -> Option<&WrappedKey> {
        self.grants.get(&folder).and_then(|g| g.get(user))
    }

    /// The wrap of a credential's content key addressed to `user`, if they hold a grant.
    #[must_use]
    pub fn credential_grant_for(&self, credential: CredentialId, user: &KeyId) -> Option<&WrappedKey> {
        self.credential_grants.get(&credential).and_then(|g| g.get(user))
    }

    /// Whether `candidate` is `ancestor` itself or sits somewhere in its subtree. Used to
    /// reject a folder move that would form a cycle. Bounded by the folder count so corrupt
    /// data (a pre-existing cycle) cannot hang the walk.
    fn is_descendant_or_self(&self, candidate: FolderId, ancestor: FolderId) -> bool {
        let mut current = candidate;
        for _ in 0..=self.folders.len() {
            if current == ancestor {
                return true;
            }
            match self.folders.get(&current).and_then(|n| n.parent) {
                Some(parent) => current = parent,
                None => return false,
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use remotino_crypto::envelope::ContentKey;
    use remotino_crypto::identity::Identity;

    fn sealed(text: &[u8]) -> SealedBlob {
        // A throwaway content key: the structural fold never opens these, so any sealed
        // blob stands in for "some encrypted content".
        ContentKey::generate().unwrap().seal(text, b"").unwrap()
    }

    fn wrap(key: &ContentKey, to: &Identity) -> WrappedKey {
        key.wrap_to(to.public()).unwrap()
    }

    #[test]
    fn folders_and_entries_fold_into_a_graph() {
        let root = FolderId::generate().unwrap();
        let child = FolderId::generate().unwrap();
        let entry = EntryId::generate().unwrap();

        let events = vec![
            Event::FolderCreated { id: root, parent: None, name: sealed(b"root") },
            Event::FolderCreated { id: child, parent: Some(root), name: sealed(b"child") },
            Event::EntryUpserted { id: entry, folder: child, data: sealed(b"srv") },
        ];
        let s = Structure::fold(&events).unwrap();

        assert_eq!(s.folders.len(), 2);
        assert_eq!(s.entries.len(), 1);
        assert_eq!(s.folders[&child].parent, Some(root));
        assert_eq!(s.entries[&entry].folder, child);
    }

    #[test]
    fn a_child_of_a_missing_parent_is_rejected() {
        // After chain verification, a dangling parent is a real inconsistency.
        let ghost = FolderId::generate().unwrap();
        let child = FolderId::generate().unwrap();
        let events = vec![Event::FolderCreated {
            id: child,
            parent: Some(ghost),
            name: sealed(b"orphan"),
        }];
        assert!(matches!(
            Structure::fold(&events),
            Err(Error::DanglingReference(_))
        ));
    }

    #[test]
    fn deleting_a_folder_takes_its_entries() {
        let f = FolderId::generate().unwrap();
        let e = EntryId::generate().unwrap();
        let events = vec![
            Event::FolderCreated { id: f, parent: None, name: sealed(b"f") },
            Event::EntryUpserted { id: e, folder: f, data: sealed(b"x") },
            Event::FolderDeleted { id: f },
        ];
        let s = Structure::fold(&events).unwrap();
        assert!(s.folders.is_empty());
        assert!(s.entries.is_empty(), "entry outlived its folder");
    }

    #[test]
    fn moving_a_folder_reparents_it_without_touching_content() {
        let a = FolderId::generate().unwrap();
        let b = FolderId::generate().unwrap();
        let entry = EntryId::generate().unwrap();
        let events = vec![
            Event::FolderCreated { id: a, parent: None, name: sealed(b"a") },
            Event::FolderCreated { id: b, parent: None, name: sealed(b"b") },
            Event::EntryUpserted { id: entry, folder: a, data: sealed(b"srv") },
            Event::FolderMoved { id: a, new_parent: Some(b) },
        ];
        let s = Structure::fold(&events).unwrap();
        assert_eq!(s.folders[&a].parent, Some(b), "a should now be under b");
        // The entry and its sealed data are untouched by the reparent.
        assert_eq!(s.entries[&entry].folder, a);
    }

    #[test]
    fn moving_a_folder_into_its_own_descendant_is_rejected() {
        let parent = FolderId::generate().unwrap();
        let child = FolderId::generate().unwrap();
        let events = vec![
            Event::FolderCreated { id: parent, parent: None, name: sealed(b"p") },
            Event::FolderCreated { id: child, parent: Some(parent), name: sealed(b"c") },
            // Moving parent under its own child would form a cycle.
            Event::FolderMoved { id: parent, new_parent: Some(child) },
        ];
        assert!(matches!(
            Structure::fold(&events),
            Err(Error::DanglingReference(_))
        ));
    }

    #[test]
    fn grant_then_revoke_updates_the_acl() {
        let alice = Identity::generate().unwrap();
        let key = ContentKey::generate().unwrap();
        let f = FolderId::generate().unwrap();

        let events = vec![
            Event::FolderCreated { id: f, parent: None, name: sealed(b"f") },
            Event::AclGranted {
                folder: f,
                grantee: alice.key_id(),
                wrapped_key: wrap(&key, &alice),
            },
        ];
        let mut s = Structure::fold(&events).unwrap();
        assert!(s.grant_for(f, &alice.key_id()).is_some());

        s.apply(&Event::AclRevoked {
            folder: f,
            grantee: alice.key_id(),
        })
        .unwrap();
        assert!(s.grant_for(f, &alice.key_id()).is_none());
    }

    #[test]
    fn the_fold_is_deterministic() {
        let f = FolderId::generate().unwrap();
        let events = vec![
            Event::FolderCreated { id: f, parent: None, name: sealed(b"f") },
            Event::FolderRenamed { id: f, name: sealed(b"renamed") },
        ];
        let a = Structure::fold(&events).unwrap();
        let b = Structure::fold(&events).unwrap();
        assert_eq!(a.folders.len(), b.folders.len());
        assert_eq!(a.folders.contains_key(&f), b.folders.contains_key(&f));
    }
}
