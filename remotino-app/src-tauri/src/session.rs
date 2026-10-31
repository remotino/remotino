//! The unlocked working session: the open repository plus the folder keys this identity
//! can write with.
//!
//! This is where the layers meet at runtime. The repository stores signed, chained
//! [`Entry`]s whose payloads are [`Event`]s. To *read* the tree we decode the events, fold
//! them, and project through the identity. To *write* we build events, sign them into
//! entries that continue the chain, and append.
//!
//! Folder content keys are recovered once on open by unwrapping the `AclGranted` events
//! addressed to this identity, and kept in memory so writing to a folder does not re-unwrap
//! every time. They never leave this process.

use std::collections::HashMap;
use std::path::Path;

use remotino_crypto::chain::{Entry, EntryBody, Head};
use remotino_crypto::envelope::ContentKey;
use remotino_crypto::identity::{Identity, KeyId, PublicIdentity};
use remotino_crypto::repository::Repository;
use remotino_crypto::Digest;
use remotino_model::event::Event;
use remotino_model::ids::{CredentialId, EntryId, FolderId};
use remotino_model::projection::build::{seal_connection, seal_credential, seal_folder_name};
use remotino_model::projection::{Connection, Credential, Projection};
use remotino_model::structure::{EnrolledUser, Structure};
use remotino_pg::{PgConfig, PgRepo};
use remotino_sql::{SqlConfig, SqlRepo};
use remotino_store::SqliteRepo;

use crate::threaded_repo::ThreadedRepo;

/// An open, unlocked session over a chain store - the local SQLite file for single-seat, or
/// a shared SQL Server for multi-user. Nothing above this line cares which.
pub struct Session {
    repo: Box<dyn Repository + Send>,
    /// Content keys for folders this identity was granted, recovered on open.
    folder_keys: HashMap<FolderId, ContentKey>,
    /// Content keys for credentials this identity holds (owned or shared to it), recovered
    /// on open from the `CredentialGranted` events addressed to it. Legacy credentials
    /// (sealed under a vault key) are read directly in the projection, not from here.
    credential_keys: HashMap<CredentialId, ContentKey>,
}

/// One row of the audit log: a signed, ordered change, as its cleartext metadata (not its
/// encrypted content).
pub struct AuditRecord {
    /// Position in the chain (0-based).
    pub seq: u64,
    /// RFC 3339 timestamp the actor recorded (informational; the chain trusts order, not it).
    pub timestamp: String,
    /// Who made the change.
    pub actor: KeyId,
    /// The kind of change, e.g. `AclGranted` - cleartext in the chain.
    pub action: String,
}

/// How much a local→shared migration copied over.
pub struct MigrationSummary {
    /// Folders re-created on the shared chain.
    pub folders: usize,
    /// Connections re-created.
    pub connections: usize,
    /// Vault credentials re-created.
    pub credentials: usize,
}

/// The audit log plus a tamper-evidence verdict from re-walking the hash links.
pub struct AuditReport {
    /// Records in chain order (oldest first).
    pub records: Vec<AuditRecord>,
    /// Whether the hash chain is unbroken (no row deleted, reordered, or edited).
    pub intact: bool,
    /// The sequence number where the chain first breaks, if it does.
    pub broken_at: Option<u64>,
}

impl Session {
    /// Wraps an already-open repository and recovers the identity's folder and vault keys.
    pub fn from_repo(
        repo: Box<dyn Repository + Send>,
        identity: &Identity,
    ) -> Result<Self, String> {
        let mut session = Self {
            repo,
            folder_keys: HashMap::new(),
            credential_keys: HashMap::new(),
        };
        session.recover_folder_keys(identity)?;
        session.recover_credential_keys(identity)?;
        Ok(session)
    }

    /// Opens the local single-seat SQLite store at `path`.
    pub fn open(path: &Path, identity: &Identity) -> Result<Self, String> {
        Self::from_repo(Box::new(SqliteRepo::open(path).map_err(err)?), identity)
    }

    /// Opens a shared SQL Server chain. `migrate` connects with admin rights and applies
    /// pending migrations (first-run / admin); otherwise it connects and only checks the
    /// schema version. The connection runs on its own thread (see `ThreadedRepo`).
    pub fn open_sql(config: &SqlConfig, identity: &Identity, migrate: bool) -> Result<Self, String> {
        let config = config.clone();
        let repo = ThreadedRepo::spawn(move || {
            let repo = if migrate {
                SqlRepo::connect_and_migrate(&config)
            } else {
                SqlRepo::connect_checked(&config)
            }
            .map_err(|e| e.to_string())?;
            Ok(Box::new(repo) as Box<dyn Repository + Send>)
        })?;
        Self::from_repo(Box::new(repo), identity)
    }

    /// Opens a shared Postgres chain, mirroring [`Session::open_sql`]. The connection runs on
    /// its own thread (`PgRepo` owns a Tokio runtime; keeping it off the Tauri runtime).
    pub fn open_pg(config: &PgConfig, identity: &Identity, migrate: bool) -> Result<Self, String> {
        let config = config.clone();
        let repo = ThreadedRepo::spawn(move || {
            let repo = if migrate {
                PgRepo::connect_and_migrate(&config)
            } else {
                PgRepo::connect_checked(&config)
            }
            .map_err(|e| e.to_string())?;
            Ok(Box::new(repo) as Box<dyn Repository + Send>)
        })?;
        Self::from_repo(Box::new(repo), identity)
    }

    /// The audit log: every entry's cleartext metadata (who acted, what kind of change, when,
    /// and in what order), plus a tamper-evidence check that re-walks the hash links. No
    /// content is decrypted - `actor`, `action` and `timestamp` live in the clear in the
    /// chain by design (`CRYPTO.md` 1), so any unlocked user can audit activity.
    pub fn audit(&self) -> Result<AuditReport, String> {
        let entries = self.repo.read_from(None).map_err(err)?;
        // Re-walk the hash links: each entry must chain to the previous one's digest, and the
        // first to genesis. A deleted, reordered, or edited row breaks a link here.
        let mut intact = true;
        let mut broken_at = None;
        let mut prev = Digest::ZERO;
        for entry in &entries {
            if entry.body.prev != prev {
                intact = false;
                broken_at = Some(entry.body.seq);
                break;
            }
            prev = entry.digest().map_err(err)?;
        }
        let records = entries
            .into_iter()
            .map(|e| AuditRecord {
                seq: e.body.seq,
                timestamp: e.body.timestamp,
                actor: e.body.actor,
                action: e.body.action,
            })
            .collect();
        Ok(AuditReport { records, intact, broken_at })
    }

    /// Every event in the log, in order. The material for a fold.
    pub fn events(&self) -> Result<Vec<Event>, String> {
        let entries = self.repo.read_from(None).map_err(err)?;
        entries
            .iter()
            .map(|e| Event::from_payload(&e.body.payload).map_err(err))
            .collect()
    }

    /// Signs `events` into entries that continue the chain, and appends them atomically.
    ///
    /// Each event becomes an entry at `head.seq + 1` linking to `head.digest`, so the
    /// batch is a valid continuation the repository will accept.
    pub fn append(&mut self, identity: &Identity, events: &[Event]) -> Result<(), String> {
        if events.is_empty() {
            return Ok(());
        }
        let mut head = self.repo.head().map_err(err)?;
        let mut entries = Vec::with_capacity(events.len());
        for event in events {
            let (seq, prev) = match head {
                Some(h) => (h.seq.checked_add(1).ok_or("sequence overflow")?, h.digest),
                None => (0, Digest::ZERO),
            };
            let body = EntryBody {
                seq,
                prev,
                // Informational only; the chain does not trust it for ordering.
                timestamp: chrono::Utc::now().to_rfc3339(),
                actor: identity.key_id(),
                action: event.action().to_owned(),
                payload: event.to_payload().map_err(err)?,
            };
            let entry = Entry::sign(body, identity).map_err(err)?;
            head = Some(Head {
                seq,
                digest: entry.digest().map_err(err)?,
            });
            entries.push(entry);
        }
        self.repo.append(&entries).map_err(err)?;
        Ok(())
    }

    /// Creates a folder: a fresh content key, a `FolderCreated`, and an `AclGranted` to
    /// self so the folder is immediately readable and writable. Returns the new id.
    pub fn create_folder(
        &mut self,
        identity: &Identity,
        parent: Option<FolderId>,
        name: &str,
    ) -> Result<FolderId, String> {
        let id = FolderId::generate().map_err(err)?;
        let key = ContentKey::generate().map_err(err)?;
        let events = vec![
            Event::FolderCreated {
                id,
                parent,
                name: seal_folder_name(&key, id, name).map_err(err)?,
            },
            Event::AclGranted {
                folder: id,
                grantee: identity.key_id(),
                wrapped_key: key.wrap_to(identity.public()).map_err(err)?,
            },
        ];
        self.append(identity, &events)?;
        self.folder_keys.insert(id, key);
        Ok(id)
    }

    /// Creates a connection entry in a folder this identity can write to.
    pub fn create_connection(
        &mut self,
        identity: &Identity,
        folder: FolderId,
        conn: &Connection,
    ) -> Result<EntryId, String> {
        let key = self
            .folder_keys
            .get(&folder)
            .ok_or("no write access to that folder")?;
        let entry = EntryId::generate().map_err(err)?;
        let event = Event::EntryUpserted {
            id: entry,
            folder,
            data: seal_connection(key, entry, conn).map_err(err)?,
        };
        // Re-borrow to satisfy the borrow checker: the seal above borrowed folder_keys.
        let event = [event];
        self.append(identity, &event)?;
        Ok(entry)
    }

    /// Deletes a connection entry.
    pub fn delete_entry(&mut self, identity: &Identity, entry: EntryId) -> Result<(), String> {
        self.append(identity, &[Event::EntryDeleted { id: entry }])
    }

    /// Deletes a folder and everything beneath it. `FolderDeleted` already takes a folder's
    /// own entries; we also emit one for every descendant folder so nothing is orphaned.
    pub fn delete_folder(&mut self, identity: &Identity, folder: FolderId) -> Result<(), String> {
        let structure = self.structure()?;
        let mut targets = vec![folder];
        let mut i = 0;
        while i < targets.len() {
            let current = targets[i];
            for (&id, node) in &structure.folders {
                if node.parent == Some(current) {
                    targets.push(id);
                }
            }
            i += 1;
        }
        let events: Vec<Event> = targets
            .into_iter()
            .map(|id| Event::FolderDeleted { id })
            .collect();
        self.append(identity, &events)
    }

    /// Renames a folder: re-seals the name under the folder's own content key.
    pub fn rename_folder(
        &mut self,
        identity: &Identity,
        folder: FolderId,
        name: &str,
    ) -> Result<(), String> {
        let key = self
            .folder_keys
            .get(&folder)
            .ok_or("no access to that folder")?;
        let sealed = seal_folder_name(key, folder, name).map_err(err)?;
        let event = [Event::FolderRenamed { id: folder, name: sealed }];
        self.append(identity, &event)
    }

    /// Renames a connection: decrypts it, changes the name, re-seals under the same folder
    /// key. Requires read+write access to the entry's folder.
    pub fn rename_entry(
        &mut self,
        identity: &Identity,
        entry: EntryId,
        name: &str,
    ) -> Result<(), String> {
        let (structure, projection) = self.decrypted(identity)?;
        let mut conn = projection
            .connections
            .get(&entry)
            .ok_or("cannot read that connection")?
            .clone();
        let folder = structure.entries.get(&entry).ok_or("no such entry")?.folder;
        let key = self
            .folder_keys
            .get(&folder)
            .ok_or("no write access to that folder")?;
        conn.name = name.to_owned();
        let data = seal_connection(key, entry, &conn).map_err(err)?;
        let event = [Event::EntryUpserted { id: entry, folder, data }];
        self.append(identity, &event)
    }

    /// Moves a connection to another folder: decrypts it with the source key and re-seals it
    /// under the destination key. Requires read on the source and write on the destination -
    /// the crypto is the access control.
    pub fn move_entry(
        &mut self,
        identity: &Identity,
        entry: EntryId,
        dest: FolderId,
    ) -> Result<(), String> {
        let (_structure, projection) = self.decrypted(identity)?;
        let conn = projection
            .connections
            .get(&entry)
            .ok_or("cannot read that connection")?
            .clone();
        let key = self
            .folder_keys
            .get(&dest)
            .ok_or("no write access to the destination folder")?;
        let data = seal_connection(key, entry, &conn).map_err(err)?;
        let event = [Event::EntryUpserted { id: entry, folder: dest, data }];
        self.append(identity, &event)
    }

    /// Moves a folder under a new parent (or to the root). Cleartext structure only - no
    /// content is re-sealed.
    pub fn move_folder(
        &mut self,
        identity: &Identity,
        folder: FolderId,
        new_parent: Option<FolderId>,
    ) -> Result<(), String> {
        self.append(identity, &[Event::FolderMoved { id: folder, new_parent }])
    }

    /// Updates a connection's fields (name, kind, host, port), preserving its folder and any
    /// linked credential. Decrypt, edit, re-seal under the same folder key.
    pub fn update_entry(
        &mut self,
        identity: &Identity,
        entry: EntryId,
        name: &str,
        kind: remotino_model::projection::ConnectionKind,
        host: &str,
        port: u16,
    ) -> Result<(), String> {
        let (structure, projection) = self.decrypted(identity)?;
        let mut conn = projection
            .connections
            .get(&entry)
            .ok_or("cannot read that connection")?
            .clone();
        let folder = structure.entries.get(&entry).ok_or("no such entry")?.folder;
        let key = self
            .folder_keys
            .get(&folder)
            .ok_or("no write access to that folder")?;
        conn.name = name.to_owned();
        conn.kind = kind;
        conn.host = host.to_owned();
        conn.port = port;
        // conn.credential_ref is preserved from the decrypted copy.
        let data = seal_connection(key, entry, &conn).map_err(err)?;
        self.append(identity, &[Event::EntryUpserted { id: entry, folder, data }])
    }

    /// Points a connection at a vault credential (or clears it). The reference is just the
    /// credential's opaque id - the secret stays in the vault, never in the connection.
    pub fn set_entry_credential(
        &mut self,
        identity: &Identity,
        entry: EntryId,
        credential: Option<CredentialId>,
    ) -> Result<(), String> {
        let (structure, projection) = self.decrypted(identity)?;
        let mut conn = projection
            .connections
            .get(&entry)
            .ok_or("cannot read that connection")?
            .clone();
        let folder = structure.entries.get(&entry).ok_or("no such entry")?.folder;
        let key = self
            .folder_keys
            .get(&folder)
            .ok_or("no write access to that folder")?;
        conn.credential_ref = credential.map(|c| c.to_string());
        let data = seal_connection(key, entry, &conn).map_err(err)?;
        self.append(identity, &[Event::EntryUpserted { id: entry, folder, data }])
    }

    /// Resolves the credential a connection points at, decrypted for use at connect time.
    /// The plaintext stays in this process - it is never returned to the webview.
    pub fn entry_credential(
        &self,
        identity: &Identity,
        entry: EntryId,
    ) -> Result<Option<Credential>, String> {
        let (_structure, projection) = self.decrypted(identity)?;
        let Some(conn) = projection.connections.get(&entry) else {
            return Ok(None);
        };
        let Some(ref_str) = &conn.credential_ref else {
            return Ok(None);
        };
        let bytes = hex::decode(ref_str).map_err(|_| "bad credential ref".to_owned())?;
        let arr: [u8; 16] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| "credential ref wrong length".to_owned())?;
        Ok(projection.credentials.get(&CredentialId(arr)).cloned())
    }

    // ---- personal vault ----

    /// Creates a credential with its own content key, wrapped to the owner so only they can
    /// read it (until they share it). Returns the new id.
    pub fn create_credential(
        &mut self,
        identity: &Identity,
        cred: &Credential,
    ) -> Result<CredentialId, String> {
        let id = CredentialId::generate().map_err(err)?;
        let key = ContentKey::generate().map_err(err)?;
        let events = vec![
            Event::CredentialUpserted {
                id,
                data: seal_credential(&key, id, cred).map_err(err)?,
            },
            Event::CredentialGranted {
                credential: id,
                grantee: identity.key_id(),
                wrapped_key: key.wrap_to(identity.public()).map_err(err)?,
            },
        ];
        self.append(identity, &events)?;
        self.credential_keys.insert(id, key);
        Ok(id)
    }

    /// Ensures a credential has its own content key, minting one (and the owner grant that
    /// records it) if this is a legacy vault-key credential being upgraded. Returns any
    /// events needed to establish the key. The caller must re-seal the credential content
    /// under the resulting `self.credential_keys[id]` so the stored blob matches the key.
    fn ensure_credential_key(
        &mut self,
        identity: &Identity,
        id: CredentialId,
    ) -> Result<Vec<Event>, String> {
        if self.credential_keys.contains_key(&id) {
            return Ok(Vec::new());
        }
        let key = ContentKey::generate().map_err(err)?;
        let grant = Event::CredentialGranted {
            credential: id,
            grantee: identity.key_id(),
            wrapped_key: key.wrap_to(identity.public()).map_err(err)?,
        };
        self.credential_keys.insert(id, key);
        Ok(vec![grant])
    }

    /// Renames a credential: decrypts it, changes the name, re-seals under its content key.
    pub fn rename_credential(
        &mut self,
        identity: &Identity,
        id: CredentialId,
        name: &str,
    ) -> Result<(), String> {
        let (_structure, projection) = self.decrypted(identity)?;
        let mut cred = projection
            .credentials
            .get(&id)
            .ok_or("no such credential")?
            .clone();
        cred.name = name.to_owned();
        let mut events = self.ensure_credential_key(identity, id)?;
        let key = self.credential_keys.get(&id).ok_or("no credential key")?;
        events.push(Event::CredentialUpserted {
            id,
            data: seal_credential(key, id, &cred).map_err(err)?,
        });
        self.append(identity, &events)
    }

    /// Updates a credential's fields. `new_secret` replaces the secret when given; otherwise
    /// the existing secret is preserved (so you can edit the username without re-typing the
    /// password).
    pub fn update_credential(
        &mut self,
        identity: &Identity,
        id: CredentialId,
        name: String,
        kind: remotino_model::projection::ConnectionKind,
        username: String,
        domain: Option<String>,
        new_secret: Option<remotino_model::projection::CredentialSecret>,
    ) -> Result<(), String> {
        let (_structure, projection) = self.decrypted(identity)?;
        let existing = projection.credentials.get(&id).ok_or("no such credential")?;
        let secret = new_secret.unwrap_or_else(|| existing.secret.clone());
        let cred = Credential { name, kind, username, domain, secret };
        let mut events = self.ensure_credential_key(identity, id)?;
        let key = self.credential_keys.get(&id).ok_or("no credential key")?;
        events.push(Event::CredentialUpserted {
            id,
            data: seal_credential(key, id, &cred).map_err(err)?,
        });
        self.append(identity, &events)
    }

    /// Deletes a credential.
    pub fn delete_credential(&mut self, identity: &Identity, id: CredentialId) -> Result<(), String> {
        self.append(identity, &[Event::CredentialDeleted { id }])
    }

    /// The key ids currently granted access to a credential (excludes legacy credentials,
    /// which have no per-credential grants).
    pub fn credential_grantees(&self, credential: CredentialId) -> Result<Vec<KeyId>, String> {
        Ok(self
            .structure()?
            .credential_grants
            .get(&credential)
            .map(|g| g.keys().copied().collect())
            .unwrap_or_default())
    }

    /// Shares a credential with an enrolled user: wraps the credential's content key to them.
    /// A legacy vault-key credential is migrated to its own key first (and its stored blob
    /// re-sealed under that key) so it can be shared. Requires that you hold the credential.
    pub fn grant_credential(
        &mut self,
        identity: &Identity,
        credential: CredentialId,
        grantee: KeyId,
    ) -> Result<(), String> {
        let grantee_identity = self
            .structure()?
            .enrolled
            .get(&grantee)
            .ok_or("that user is not enrolled")?
            .identity
            .clone();
        let (_structure, projection) = self.decrypted(identity)?;
        let cred = projection
            .credentials
            .get(&credential)
            .ok_or("cannot read that credential")?
            .clone();
        let mut events = self.ensure_credential_key(identity, credential)?;
        let key = self.credential_keys.get(&credential).ok_or("no credential key")?;
        // Re-seal under the per-credential key. Harmless if already sealed under it; needed
        // when a legacy credential was just migrated from its vault key.
        events.push(Event::CredentialUpserted {
            id: credential,
            data: seal_credential(key, credential, &cred).map_err(err)?,
        });
        events.push(Event::CredentialGranted {
            credential,
            grantee,
            wrapped_key: key.wrap_to(&grantee_identity).map_err(err)?,
        });
        self.append(identity, &events)
    }

    /// Revokes a user's access to a credential. Forward-only, exactly like `revoke_folder`.
    pub fn revoke_credential(
        &mut self,
        identity: &Identity,
        credential: CredentialId,
        grantee: KeyId,
    ) -> Result<(), String> {
        self.append(identity, &[Event::CredentialRevoked { credential, grantee }])
    }

    fn recover_credential_keys(&mut self, identity: &Identity) -> Result<(), String> {
        let me = identity.key_id();
        for event in self.events()? {
            if let Event::CredentialGranted {
                credential,
                grantee,
                wrapped_key,
            } = event
            {
                if grantee == me {
                    if let Ok(key) = ContentKey::unwrap_for(&wrapped_key, identity) {
                        self.credential_keys.insert(credential, key);
                    }
                }
            }
        }
        Ok(())
    }

    // ---- multi-user: enrolment and folder sharing ----

    /// Enrolls a user by their public identity, so folders can be shared with them.
    pub fn enroll_user(
        &mut self,
        identity: &Identity,
        name: String,
        public_identity: PublicIdentity,
    ) -> Result<(), String> {
        self.append(
            identity,
            &[Event::UserEnrolled { name, identity: public_identity }],
        )
    }

    /// Every enrolled user.
    pub fn enrolled_users(&self) -> Result<Vec<EnrolledUser>, String> {
        Ok(self.structure()?.enrolled.into_values().collect())
    }

    /// The key ids currently granted read access to a folder.
    pub fn folder_grantees(&self, folder: FolderId) -> Result<Vec<KeyId>, String> {
        Ok(self
            .structure()?
            .grants
            .get(&folder)
            .map(|g| g.keys().copied().collect())
            .unwrap_or_default())
    }

    /// Grants a user read access to a folder: wraps the folder's content key to their public
    /// identity. Requires that you hold the folder key and the user is enrolled.
    pub fn grant_folder(
        &mut self,
        identity: &Identity,
        folder: FolderId,
        grantee: KeyId,
    ) -> Result<(), String> {
        let grantee_identity = self
            .structure()?
            .enrolled
            .get(&grantee)
            .ok_or("that user is not enrolled")?
            .identity
            .clone();
        let key = self
            .folder_keys
            .get(&folder)
            .ok_or("you don't have access to that folder")?;
        let wrapped_key = key.wrap_to(&grantee_identity).map_err(err)?;
        self.append(
            identity,
            &[Event::AclGranted { folder, grantee, wrapped_key }],
        )
    }

    /// Revokes a user's access to a folder. Forward-only (`CRYPTO.md` 6): removes the grant
    /// so no *new* reads succeed; a key rotation to cut off cached access is a later step.
    pub fn revoke_folder(
        &mut self,
        identity: &Identity,
        folder: FolderId,
        grantee: KeyId,
    ) -> Result<(), String> {
        self.append(identity, &[Event::AclRevoked { folder, grantee }])
    }

    /// Replays everything this identity can read in `source` (typically the local single-seat
    /// store) into this session as **brand-new** events: folders, connections and vault
    /// credentials are re-created and re-sealed on this chain with fresh ids, so nothing links
    /// back to the source chain. Sharing/enrolments are not carried (the local store is
    /// single-seat). Returns how many of each were migrated.
    ///
    /// Refuses if this (target) session already holds readable folders, connections or
    /// credentials, so a re-run can't silently duplicate a tree.
    pub fn migrate_from(
        &mut self,
        identity: &Identity,
        source: &Session,
    ) -> Result<MigrationSummary, String> {
        let (target_structure, target_projection) = self.decrypted(identity)?;
        let target_has_content = !target_projection.connections.is_empty()
            || !target_projection.credentials.is_empty()
            || target_structure
                .folders
                .keys()
                .any(|f| target_projection.folders.get(f).is_some_and(|v| v.readable));
        if target_has_content {
            return Err("the shared database already has entries — migration only runs into a fresh one".to_owned());
        }

        let (structure, projection) = source.decrypted(identity)?;

        // 1. Credentials first, so migrated connections can point at the new ids.
        let mut cred_map: HashMap<CredentialId, CredentialId> = HashMap::new();
        for (old_id, cred) in &projection.credentials {
            let new_id = self.create_credential(identity, cred)?;
            cred_map.insert(*old_id, new_id);
        }

        // 2. Folders, parents before children, remapping the parent to its new id. Only
        //    readable folders (name present) can be recreated - the single-seat store owns all
        //    of its folders, so that is every folder.
        let mut folder_map: HashMap<FolderId, FolderId> = HashMap::new();
        let mut remaining: Vec<FolderId> = projection
            .folders
            .iter()
            .filter(|(_, vf)| vf.name.is_some())
            .map(|(id, _)| *id)
            .collect();
        while !remaining.is_empty() {
            let mut still: Vec<FolderId> = Vec::new();
            let mut progressed = false;
            for fid in remaining {
                let Some(vf) = projection.folders.get(&fid) else { continue };
                let Some(name) = &vf.name else { continue };
                let parent_ready = vf.parent.is_none_or(|p| folder_map.contains_key(&p));
                if !parent_ready {
                    still.push(fid);
                    continue;
                }
                let new_parent = vf.parent.and_then(|p| folder_map.get(&p).copied());
                let new_id = self.create_folder(identity, new_parent, name)?;
                folder_map.insert(fid, new_id);
                progressed = true;
            }
            remaining = still;
            if !progressed {
                break; // parents we can't resolve (shouldn't happen single-seat); stop cleanly
            }
        }

        // 3. Connections, remapping their folder and any credential reference.
        let mut connections = 0usize;
        for (entry_id, conn) in &projection.connections {
            let Some(node) = structure.entries.get(entry_id) else { continue };
            let Some(&new_folder) = folder_map.get(&node.folder) else { continue };
            let mut c = conn.clone();
            c.credential_ref = conn.credential_ref.as_deref().and_then(|r| {
                let bytes = hex::decode(r).ok()?;
                let arr: [u8; 16] = bytes.as_slice().try_into().ok()?;
                cred_map.get(&CredentialId(arr)).map(|n| n.to_string())
            });
            self.create_connection(identity, new_folder, &c)?;
            connections += 1;
        }

        Ok(MigrationSummary {
            folders: folder_map.len(),
            connections,
            credentials: cred_map.len(),
        })
    }

    /// Folds the current log into a structure.
    fn structure(&self) -> Result<Structure, String> {
        Structure::fold(&self.events()?).map_err(err)
    }

    /// The structure plus the projection this identity can read.
    fn decrypted(&self, identity: &Identity) -> Result<(Structure, Projection), String> {
        let structure = self.structure()?;
        let projection = Projection::project(&structure, identity).map_err(err)?;
        Ok((structure, projection))
    }

    fn recover_folder_keys(&mut self, identity: &Identity) -> Result<(), String> {
        let me = identity.key_id();
        for event in self.events()? {
            if let Event::AclGranted {
                folder,
                grantee,
                wrapped_key,
            } = event
            {
                if grantee == me {
                    if let Ok(key) = ContentKey::unwrap_for(&wrapped_key, identity) {
                        self.folder_keys.insert(folder, key);
                    }
                }
            }
        }
        Ok(())
    }
}

fn err<E: core::fmt::Display>(e: E) -> String {
    e.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use remotino_model::projection::{Connection, ConnectionKind, Credential, CredentialSecret};
    use std::sync::atomic::{AtomicU64, Ordering};

    // A unique throwaway SQLite path under the temp dir (one per call).
    fn temp_db(tag: &str) -> std::path::PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let mut p = std::env::temp_dir();
        p.push(format!("remotino_migtest_{tag}_{}_{n}.db", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn migrate_from_replays_tree_and_vault_with_fresh_ids() {
        let id = Identity::generate().expect("identity");

        // Source: a nested tree (Prod > DBs), a vault credential, and a connection linked to it.
        let src_path = temp_db("src");
        let mut src = Session::open(&src_path, &id).expect("open src");
        let cred = Credential {
            name: "root".to_owned(),
            kind: ConnectionKind::Ssh,
            username: "root".to_owned(),
            domain: None,
            secret: CredentialSecret::Password { password: "s3cret".to_owned() },
        };
        let src_cred = src.create_credential(&id, &cred).expect("cred");
        let parent = src.create_folder(&id, None, "Prod").expect("parent");
        let child = src.create_folder(&id, Some(parent), "DBs").expect("child");
        let linked = Connection {
            kind: ConnectionKind::Ssh,
            name: "db-01".to_owned(),
            host: "10.0.0.5".to_owned(),
            port: 22,
            credential_ref: Some(src_cred.to_string()),
        };
        src.create_connection(&id, child, &linked).expect("linked conn");
        let plain = Connection {
            kind: ConnectionKind::Rdp,
            name: "dc-01".to_owned(),
            host: "10.0.0.1".to_owned(),
            port: 3389,
            credential_ref: None,
        };
        src.create_connection(&id, parent, &plain).expect("plain conn");

        // Migrate into a fresh target.
        let dst_path = temp_db("dst");
        let mut dst = Session::open(&dst_path, &id).expect("open dst");
        let summary = dst.migrate_from(&id, &src).expect("migrate");
        assert_eq!(summary.folders, 2);
        assert_eq!(summary.connections, 2);
        assert_eq!(summary.credentials, 1);

        // The target projects the same tree.
        let (_structure, proj) = dst.decrypted(&id).expect("decrypt dst");
        assert_eq!(proj.folders.len(), 2);
        assert_eq!(proj.connections.len(), 2);
        assert_eq!(proj.credentials.len(), 1);

        // Hierarchy preserved: one root named "Prod" with a child named "DBs".
        let root = proj
            .folders
            .iter()
            .find(|(_, f)| f.parent.is_none())
            .expect("a root folder");
        assert_eq!(root.1.name.as_deref(), Some("Prod"));
        let child_ok = proj
            .folders
            .values()
            .any(|f| f.parent == Some(*root.0) && f.name.as_deref() == Some("DBs"));
        assert!(child_ok, "child folder re-parented under the new root");

        // The linked connection points at the *new* credential id (regenerated, not the source's).
        let db01 = proj.connections.values().find(|c| c.name == "db-01").expect("db-01");
        let new_ref = db01.credential_ref.as_ref().expect("credential link kept");
        assert_ne!(new_ref, &src_cred.to_string(), "ids must be regenerated");
        let bytes = hex::decode(new_ref).expect("hex ref");
        let arr: [u8; 16] = bytes.as_slice().try_into().expect("16 bytes");
        assert!(
            proj.credentials.contains_key(&CredentialId(arr)),
            "the new ref resolves to a migrated credential"
        );

        // Re-running refuses: the target already has content, so it can't duplicate.
        assert!(dst.migrate_from(&id, &src).is_err(), "second migration must refuse");

        let _ = std::fs::remove_file(&src_path);
        let _ = std::fs::remove_file(&dst_path);
    }
}
