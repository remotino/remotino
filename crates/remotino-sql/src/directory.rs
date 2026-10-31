//! Public-identity directory and per-user vault storage.
//!
//! Both tables hold data the server cannot read: `Identities` is public keys (integrity
//! comes from the audit chain, not the table), and `Vaults` is sealed to each owner. The
//! backend stores and returns opaque bytes and never interprets them.
//!
//! # Enrolment is not authentication
//!
//! Writing a row into `Identities` records that *someone* published a public key. Nothing
//! here proves it is really that person's - that requires out-of-band fingerprint
//! comparison (`CRYPTO.md` 9.2). This module deliberately offers no "is this the real
//! Alice?" answer, because it cannot have one.

use remotino_crypto::identity::{KeyId, PublicIdentity};

use crate::repo::SqlRepo;
use crate::{Error, Result};

/// A user's sealed vault, as opaque bytes. The server cannot open it.
#[derive(Debug, Clone)]
pub struct SealedVault(pub Vec<u8>);

/// Serialises a public identity to CBOR.
///
/// The crypto crate keeps `PublicIdentity`'s fields private to force construction through
/// its canonical-encoding check, so this backend goes through serde rather than touching
/// fields. `from_bytes` below round-trips through the same guard, so a blob that decodes
/// to a non-canonical key is rejected there, not silently stored.
fn identity_to_bytes(identity: &PublicIdentity) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::into_writer(identity, &mut buf).map_err(|_| Error::MalformedRow {
        seq: -1,
        reason: "could not encode public identity",
    })?;
    Ok(buf)
}

/// Deserialises a public identity from CBOR, enforcing the canonical-encoding check.
fn identity_from_bytes(bytes: &[u8]) -> Result<PublicIdentity> {
    ciborium::from_reader(bytes).map_err(|_| Error::MalformedRow {
        seq: -1,
        reason: "stored identity failed canonical decode",
    })
}

impl SqlRepo {
    /// Publishes a public identity.
    ///
    /// Idempotent on `key_id`: re-publishing the same identity is a no-op, and publishing
    /// a *different* blob under an existing `key_id` is refused. A `key_id` is a hash of
    /// the very keys in the blob (`CRYPTO.md` 4), so a mismatch means someone is trying to
    /// bind an id to keys that do not produce it - reject rather than overwrite.
    ///
    /// # Errors
    ///
    /// [`Error::IdentityConflict`] if the id already maps to different bytes; otherwise
    /// SQL failures.
    pub fn put_identity(&mut self, identity: &PublicIdentity) -> Result<()> {
        let key_id = identity.key_id();
        let blob = identity_to_bytes(identity)?;

        if let Some(existing) = self.get_identity_bytes(key_id)? {
            return if existing == blob {
                Ok(())
            } else {
                Err(Error::IdentityConflict { key_id })
            };
        }

        self.with_client(|client| Box::pin(async move {
            client
                .execute(
                    "INSERT INTO dbo.Identities (key_id, public_blob) VALUES (@P1, @P2);",
                    &[&key_id.0 .0.as_slice(), &blob.as_slice()],
                )
                .await?;
            Ok(())
        }))
    }

    /// Fetches a public identity by id.
    ///
    /// # Errors
    ///
    /// SQL failures, or [`Error::MalformedRow`] if the stored bytes do not decode - which
    /// for an identity means the canonical-encoding check refused them (`CRYPTO.md` 4).
    pub fn get_identity(&self, key_id: KeyId) -> Result<Option<PublicIdentity>> {
        let Some(blob) = self.get_identity_bytes(key_id)? else {
            return Ok(None);
        };
        Ok(Some(identity_from_bytes(&blob)?))
    }

    /// Returns a resolver closure over the whole directory, for `verify_chain`.
    ///
    /// Loads every identity once. For the scale this tool targets - tens of users - that
    /// is a single small query, and it means chain verification does not issue a round
    /// trip per entry.
    ///
    /// # Errors
    ///
    /// SQL failures, or a stored identity that fails canonical decode.
    pub fn load_directory(&self) -> Result<std::collections::HashMap<KeyId, PublicIdentity>> {
        let rows = self.with_client(|client| Box::pin(async move {
            Ok(client
                .query("SELECT public_blob FROM dbo.Identities;", &[])
                .await?
                .into_first_result()
                .await?)
        }))?;

        let mut dir = std::collections::HashMap::with_capacity(rows.len());
        for row in rows {
            let blob: &[u8] = row.get(0).ok_or(Error::MalformedRow {
                seq: -1,
                reason: "identity blob was null",
            })?;
            let identity = identity_from_bytes(blob)?;
            dir.insert(identity.key_id(), identity);
        }
        Ok(dir)
    }

    /// Stores or replaces a user's sealed vault.
    ///
    /// Unlike identities, a vault legitimately changes - a user adds credentials - so this
    /// is an upsert. Row ownership (one user cannot overwrite another's vault) is a
    /// server-side concern via row-level security in a shared deployment; the blob is
    /// sealed to its owner regardless, so this is an availability control, not a
    /// confidentiality one (`DESIGN.md` 3).
    ///
    /// # Errors
    ///
    /// SQL failures.
    pub fn put_vault(&mut self, owner: KeyId, vault: &SealedVault) -> Result<()> {
        // Copy out of the borrow before the boxed future captures it: the future may
        // outlive the `&SealedVault` argument, and the bytes are small.
        let blob = vault.0.clone();
        self.with_client(move |client| {
            Box::pin(async move {
                client
                    .execute(
                        "MERGE dbo.Vaults AS target
                         USING (SELECT @P1 AS key_id) AS src ON target.key_id = src.key_id
                         WHEN MATCHED THEN UPDATE SET sealed_blob = @P2
                         WHEN NOT MATCHED THEN INSERT (key_id, sealed_blob) VALUES (@P1, @P2);",
                        &[&owner.0 .0.as_slice(), &blob.as_slice()],
                    )
                    .await?;
                Ok(())
            })
        })
    }

    /// Fetches a user's sealed vault.
    ///
    /// # Errors
    ///
    /// SQL failures.
    pub fn get_vault(&self, owner: KeyId) -> Result<Option<SealedVault>> {
        let row = self.with_client(|client| Box::pin(async move {
            Ok(client
                .query(
                    "SELECT sealed_blob FROM dbo.Vaults WHERE key_id = @P1;",
                    &[&owner.0 .0.as_slice()],
                )
                .await?
                .into_row()
                .await?)
        }))?;
        Ok(row.and_then(|r| r.get::<&[u8], _>(0).map(|b| SealedVault(b.to_vec()))))
    }

    fn get_identity_bytes(&self, key_id: KeyId) -> Result<Option<Vec<u8>>> {
        let row = self.with_client(|client| Box::pin(async move {
            Ok(client
                .query(
                    "SELECT public_blob FROM dbo.Identities WHERE key_id = @P1;",
                    &[&key_id.0 .0.as_slice()],
                )
                .await?
                .into_row()
                .await?)
        }))?;
        Ok(row.and_then(|r| r.get::<&[u8], _>(0).map(<[u8]>::to_vec)))
    }
}
