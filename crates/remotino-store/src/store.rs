//! [`SqliteRepo`]: a [`Repository`] over a local SQLite file.

use std::path::Path;

use remotino_crypto::chain::{Entry, Head, Seq};
use remotino_crypto::repository::Repository;
use remotino_crypto::Digest;
use rusqlite::Connection;

use crate::{Error, Result};

/// A single-seat chain store backed by SQLite.
///
/// Answers the same contract as `MemoryRepo` and `SqlRepo`: `append` rejects anything that
/// does not extend the current head contiguously, `read_from` returns ascending order, and
/// entries round-trip through [`Entry::from_bytes`] so a hand-edited non-canonical row is
/// refused at read.
#[derive(Debug)]
pub struct SqliteRepo {
    conn: Connection,
}

impl SqliteRepo {
    /// Opens (or creates) a store at `path`.
    ///
    /// # Errors
    ///
    /// SQLite failures.
    pub fn open(path: &Path) -> Result<Self> {
        Self::init(Connection::open(path)?)
    }

    /// Opens an in-memory store. Test support.
    ///
    /// # Errors
    ///
    /// SQLite failures.
    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.pragma_update(None, "journal_mode", "WAL")?;
        // `body` is the canonical entry encoding, verbatim - mirroring the SQL backend's
        // `body` column so both decode through the same `Entry::from_bytes`. `entry_hash`
        // is unique, the same content-address guarantee the server enforces.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS events (
                 seq         INTEGER PRIMARY KEY,
                 prev_hash   BLOB NOT NULL,
                 entry_hash  BLOB NOT NULL UNIQUE,
                 body        BLOB NOT NULL
             );",
        )?;
        Ok(Self { conn })
    }
}

impl Repository for SqliteRepo {
    fn append(&mut self, entries: &[Entry]) -> remotino_crypto::Result<Head> {
        use remotino_crypto::Error as CryptoError;

        if entries.is_empty() {
            return Err(CryptoError::ChainIntegrity("empty append"));
        }

        // Validate the whole batch against the current head before writing, so a bad batch
        // leaves the store untouched. Mirrors MemoryRepo exactly.
        let mut head = self.head()?;
        for entry in entries {
            match head {
                None => {
                    if entry.body.seq != 0 || entry.body.prev != Digest::ZERO {
                        return Err(CryptoError::ChainIntegrity(
                            "append does not start at genesis on an empty repository",
                        ));
                    }
                }
                Some(h) => {
                    let next = h
                        .seq
                        .checked_add(1)
                        .ok_or(CryptoError::ChainIntegrity("sequence overflow"))?;
                    if entry.body.seq != next {
                        return Err(CryptoError::ChainIntegrity("append leaves a sequence gap"));
                    }
                    if entry.body.prev != h.digest {
                        return Err(CryptoError::ChainIntegrity("append breaks the hash link"));
                    }
                }
            }
            head = Some(Head {
                seq: entry.body.seq,
                digest: entry.digest()?,
            });
        }

        let tx = self
            .conn
            .transaction()
            .map_err(|_| CryptoError::Encoding("sqlite transaction"))?;
        for entry in entries {
            let body = entry.to_bytes()?;
            let digest = entry.digest()?;
            let seq = i64::try_from(entry.body.seq)
                .map_err(|_| CryptoError::Malformed("sequence exceeds i64"))?;
            tx.execute(
                "INSERT INTO events (seq, prev_hash, entry_hash, body) VALUES (?1, ?2, ?3, ?4);",
                rusqlite::params![seq, entry.body.prev.0.as_slice(), digest.0.as_slice(), body],
            )
            .map_err(|_| CryptoError::Encoding("sqlite insert"))?;
        }
        tx.commit()
            .map_err(|_| CryptoError::Encoding("sqlite commit"))?;

        head.ok_or(CryptoError::ChainIntegrity("append produced an empty chain"))
    }

    fn read_from(&self, after: Option<Seq>) -> remotino_crypto::Result<Vec<Entry>> {
        // ORDER BY seq is contractual: verify_chain walks the slice in order.
        let bodies = self
            .read_bodies(after)
            .map_err(|_| remotino_crypto::Error::Encoding("sqlite read"))?;
        let mut entries = Vec::with_capacity(bodies.len());
        for body in bodies {
            // Same canonical gate as every other backend: a non-canonical row is refused.
            entries.push(Entry::from_bytes(&body)?);
        }
        Ok(entries)
    }

    fn head(&self) -> remotino_crypto::Result<Option<Head>> {
        self.head_inner()
            .map_err(|_| remotino_crypto::Error::Encoding("sqlite head"))
    }
}

impl SqliteRepo {
    fn read_bodies(&self, after: Option<Seq>) -> Result<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        match after {
            None => {
                let mut stmt = self
                    .conn
                    .prepare("SELECT body FROM events ORDER BY seq ASC;")?;
                let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
                for r in rows {
                    out.push(r?);
                }
            }
            Some(seq) => {
                let seq = i64::try_from(seq).map_err(|_| Error::MalformedRow {
                    seq: -1,
                    reason: "cursor exceeds i64",
                })?;
                let mut stmt = self
                    .conn
                    .prepare("SELECT body FROM events WHERE seq > ?1 ORDER BY seq ASC;")?;
                let rows = stmt.query_map([seq], |r| r.get::<_, Vec<u8>>(0))?;
                for r in rows {
                    out.push(r?);
                }
            }
        }
        Ok(out)
    }

    fn head_inner(&self) -> Result<Option<Head>> {
        let row = self
            .conn
            .query_row(
                "SELECT seq, entry_hash FROM events ORDER BY seq DESC LIMIT 1;",
                [],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)),
            )
            .ok();
        let Some((seq, digest_bytes)) = row else {
            return Ok(None);
        };
        let digest: [u8; 32] = digest_bytes.as_slice().try_into().map_err(|_| Error::MalformedRow {
            seq,
            reason: "entry_hash not 32 bytes",
        })?;
        let seq = u64::try_from(seq).map_err(|_| Error::MalformedRow {
            seq,
            reason: "negative sequence",
        })?;
        Ok(Some(Head {
            seq,
            digest: Digest(digest),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use remotino_crypto::chain::{self, Entry, EntryBody};
    use remotino_crypto::identity::{Identity, KeyId, PublicIdentity};
    use remotino_crypto::repository::MemoryRepo;
    use std::collections::HashMap;

    fn entry(seq: Seq, prev: Digest, id: &Identity) -> Entry {
        Entry::sign(
            EntryBody {
                seq,
                prev,
                timestamp: "2026-07-24T00:00:00Z".to_owned(),
                actor: id.key_id(),
                action: "Test".to_owned(),
                payload: vec![1, 2, 3],
            },
            id,
        )
        .unwrap()
    }

    fn chain_of(len: u64, id: &Identity) -> Vec<Entry> {
        let mut out = Vec::new();
        let mut prev = Digest::ZERO;
        for seq in 0..len {
            let e = entry(seq, prev, id);
            prev = e.digest().unwrap();
            out.push(e);
        }
        out
    }

    fn dir(id: &Identity) -> HashMap<KeyId, PublicIdentity> {
        let mut d = HashMap::new();
        d.insert(id.key_id(), id.public().clone());
        d
    }

    #[test]
    fn append_read_head_roundtrip() {
        let id = Identity::generate().unwrap();
        let mut repo = SqliteRepo::open_in_memory().unwrap();
        assert!(repo.head().unwrap().is_none());

        let head = repo.append(&chain_of(5, &id)).unwrap();
        assert_eq!(head.seq, 4);
        assert_eq!(repo.read_from(None).unwrap().len(), 5);
        assert_eq!(repo.head().unwrap().unwrap(), head);
    }

    #[test]
    fn stored_chain_still_verifies() {
        let id = Identity::generate().unwrap();
        let d = dir(&id);
        let mut repo = SqliteRepo::open_in_memory().unwrap();
        repo.append(&chain_of(4, &id)).unwrap();
        let read = repo.read_from(None).unwrap();
        let head = chain::verify_chain(&read, None, |k| d.get(k).cloned()).unwrap();
        assert_eq!(head.seq, 3);
    }

    #[test]
    fn incremental_read() {
        let id = Identity::generate().unwrap();
        let mut repo = SqliteRepo::open_in_memory().unwrap();
        repo.append(&chain_of(6, &id)).unwrap();
        let fresh = repo.read_from(Some(3)).unwrap();
        assert_eq!(fresh.len(), 2);
        assert_eq!(fresh.first().unwrap().body.seq, 4);
    }

    #[test]
    fn sqlite_and_memory_agree_including_rejections() {
        // The conformance point: SqliteRepo behaves identically to the reference impl on
        // success and on every rejection.
        let id = Identity::generate().unwrap();
        let mut sq = SqliteRepo::open_in_memory().unwrap();
        let mut mem = MemoryRepo::new();
        let entries = chain_of(3, &id);
        assert_eq!(sq.append(&entries).unwrap(), mem.append(&entries).unwrap());

        let orphan = entry(99, Digest::of(b"nowhere"), &id);
        assert!(sq.append(std::slice::from_ref(&orphan)).is_err());
        assert!(mem.append(&[orphan]).is_err());
        assert!(sq.append(&[]).is_err());
        assert!(mem.append(&[]).is_err());
    }

    #[test]
    fn a_gap_is_rejected_and_nothing_lands() {
        let id = Identity::generate().unwrap();
        let mut repo = SqliteRepo::open_in_memory().unwrap();
        repo.append(&chain_of(2, &id)).unwrap();
        let before = repo.head().unwrap();
        let mut bad = chain_of(2, &id);
        bad.push(entry(99, Digest::of(b"gap"), &id));
        assert!(repo.append(&bad).is_err());
        assert_eq!(repo.head().unwrap(), before);
    }

    #[test]
    fn persists_across_reopen() {
        let id = Identity::generate().unwrap();
        let path = std::env::temp_dir().join(format!("remotino-store-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        {
            let mut repo = SqliteRepo::open(&path).unwrap();
            repo.append(&chain_of(3, &id)).unwrap();
        }
        {
            let repo = SqliteRepo::open(&path).unwrap();
            assert_eq!(repo.head().unwrap().unwrap().seq, 2);
            assert_eq!(repo.read_from(None).unwrap().len(), 3);
        }
        let _ = std::fs::remove_file(&path);
    }
}
