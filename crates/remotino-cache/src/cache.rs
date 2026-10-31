//! The SQLite-backed cache.


use std::path::Path;

use remotino_crypto::chain::{self, Entry, Head, Seq};
use remotino_crypto::identity::{KeyId, PublicIdentity};
use remotino_crypto::Digest;
use rusqlite::Connection;

use crate::{Error, Result};

/// A local cache of verified chain entries.
///
/// Backed by SQLite, but that is an implementation detail: nothing outside this crate
/// depends on it being SQLite, and the file is disposable - deleting it costs a resync,
/// not data, because the server is the source of truth.
#[derive(Debug)]
pub struct Cache {
    conn: Connection,
}

impl Cache {
    /// Opens (or creates) a cache at `path`.
    ///
    /// # Errors
    ///
    /// SQLite failures, e.g. an unwritable directory.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        Self::init(conn)
    }

    /// Opens an in-memory cache. Test support, and a valid "no persistence" mode.
    ///
    /// # Errors
    ///
    /// SQLite failures.
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::init(conn)
    }

    fn init(conn: Connection) -> Result<Self> {
        // WAL for concurrent read during write, and a foreign-key-free single-table
        // schema: the cache is a flat mirror, not a relational model. `entry_bytes` holds
        // the canonical encoding verbatim, mirroring the SQL backend's `body` column, so
        // both sides decode through the same `Entry::from_bytes`.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS entries (
                 seq          INTEGER PRIMARY KEY,
                 entry_bytes  BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS meta (
                 key   TEXT PRIMARY KEY,
                 value BLOB NOT NULL
             );",
        )?;
        Ok(Self { conn })
    }

    /// The sync cursor: the highest sequence this cache has stored, or `None` if empty.
    ///
    /// This is what the caller passes to the server's `read_from` to fetch only new
    /// entries. Derived from the table rather than stored separately, so it can never
    /// disagree with the rows.
    ///
    /// # Errors
    ///
    /// SQLite failures.
    pub fn cursor(&self) -> Result<Option<Seq>> {
        let seq: Option<i64> = self
            .conn
            .query_row("SELECT MAX(seq) FROM entries;", [], |r| r.get(0))?;
        Ok(seq.and_then(|s| u64::try_from(s).ok()))
    }

    /// Loads the cached chain and **re-verifies it** before returning.
    ///
    /// This is the load path, and its contract is the important one: it never returns
    /// unverified entries. `resolve` supplies public identities (the caller's directory).
    /// If verification fails - a tampered file, a directory that no longer contains a
    /// signer - the cache is treated as unusable and the caller should discard and
    /// resync. That decision is surfaced as [`LoadOutcome::Unusable`] rather than an
    /// `Err`, because a bad cache is an expected, recoverable condition, not a fault.
    ///
    /// # Errors
    ///
    /// SQLite failures, or a stored entry that fails canonical decode (which is corruption
    /// and also yields [`LoadOutcome::Unusable`] rather than propagating, except where the
    /// SQLite layer itself errors).
    pub fn load_verified<F>(&self, resolve: F) -> Result<LoadOutcome>
    where
        F: FnMut(&KeyId) -> Option<PublicIdentity>,
    {
        let entries = match self.read_all_entries() {
            Ok(e) => e,
            // A decode failure is corruption, not a fault to bubble up: the caller's
            // remedy is identical to a verification failure - discard and resync.
            Err(Error::Corrupt(_)) | Err(Error::Crypto(_)) => {
                return Ok(LoadOutcome::Unusable);
            }
            Err(other) => return Err(other),
        };

        if entries.is_empty() {
            return Ok(LoadOutcome::Empty);
        }

        match chain::verify_chain(&entries, None, resolve) {
            Ok(head) => Ok(LoadOutcome::Verified { entries, head }),
            Err(_) => Ok(LoadOutcome::Unusable),
        }
    }

    /// Appends already-verified entries, extending the cache.
    ///
    /// The caller is responsible for having verified `entries` as a continuation of the
    /// current head via `verify_chain(delta, Some(head), ..)`; this method re-checks the
    /// structural join (seq contiguity and link) as a guard against a caller mistake, but
    /// does **not** re-run signature verification - that is the caller's job with the
    /// directory it holds. Passing unverified entries here would poison the cache.
    ///
    /// Atomic: either the whole batch lands or none of it does.
    ///
    /// # Errors
    ///
    /// SQLite failures, or [`Error::Crypto`] if the batch does not structurally continue
    /// the cache.
    pub fn append_verified(&mut self, entries: &[Entry]) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }

        let mut expected = self.cursor()?;
        let mut expected_prev = self.stored_head()?;

        let tx = self.conn.transaction()?;
        for entry in entries {
            // Structural continuation check. Not a security boundary - the caller already
            // verified signatures - but it stops a caller bug from silently creating a
            // cache that will fail its own load-time re-verification later.
            match (expected, expected_prev) {
                (None, _) => {
                    if entry.body.seq != 0 || entry.body.prev != Digest::ZERO {
                        return Err(Error::Crypto(remotino_crypto::Error::ChainIntegrity(
                            "cache append does not start at genesis",
                        )));
                    }
                }
                (Some(prev_seq), Some(prev_head)) => {
                    let next = prev_seq.checked_add(1).ok_or(Error::Crypto(
                        remotino_crypto::Error::ChainIntegrity("cache sequence overflow"),
                    ))?;
                    if entry.body.seq != next {
                        return Err(Error::Crypto(remotino_crypto::Error::ChainIntegrity(
                            "cache append leaves a gap",
                        )));
                    }
                    if entry.body.prev != prev_head.digest {
                        return Err(Error::Crypto(remotino_crypto::Error::ChainIntegrity(
                            "cache append breaks the link",
                        )));
                    }
                }
                (Some(_), None) => {
                    return Err(Error::Corrupt("cursor without a head"));
                }
            }

            let bytes = entry.to_bytes().map_err(Error::Crypto)?;
            let seq = i64::try_from(entry.body.seq)
                .map_err(|_| Error::Corrupt("sequence exceeds i64"))?;
            tx.execute(
                "INSERT INTO entries (seq, entry_bytes) VALUES (?1, ?2);",
                rusqlite::params![seq, bytes],
            )?;

            let digest = entry.digest().map_err(Error::Crypto)?;
            expected = Some(entry.body.seq);
            expected_prev = Some(Head {
                seq: entry.body.seq,
                digest,
            });
        }

        // Persist the pinned head alongside the rows, in the same transaction, so the two
        // can never disagree.
        if let Some(head) = expected_prev {
            let mut buf = Vec::with_capacity(40);
            buf.extend_from_slice(&head.seq.to_le_bytes());
            buf.extend_from_slice(&head.digest.0);
            tx.execute(
                "INSERT INTO meta (key, value) VALUES ('head', ?1)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value;",
                rusqlite::params![buf],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    /// Discards everything, for a resync after a cache is found unusable.
    ///
    /// # Errors
    ///
    /// SQLite failures.
    pub fn clear(&mut self) -> Result<()> {
        self.conn
            .execute_batch("DELETE FROM entries; DELETE FROM meta;")?;
        Ok(())
    }

    /// The pinned head recorded at the last append, if any.
    ///
    /// Used for the truncation alarm: if the server later reports a head at a lower seq,
    /// or a different digest at the same seq, that is a rollback
    /// ([`Head::check_not_rewound`]).
    ///
    /// # Errors
    ///
    /// SQLite failures, or [`Error::Corrupt`] if the stored head is malformed.
    pub fn stored_head(&self) -> Result<Option<Head>> {
        let bytes: Option<Vec<u8>> = self
            .conn
            .query_row("SELECT value FROM meta WHERE key = 'head';", [], |r| r.get(0))
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })?;

        let Some(bytes) = bytes else { return Ok(None) };
        if bytes.len() != 40 {
            return Err(Error::Corrupt("stored head is not 40 bytes"));
        }
        let seq_bytes: [u8; 8] = bytes
            .get(..8)
            .and_then(|s| s.try_into().ok())
            .ok_or(Error::Corrupt("stored head seq"))?;
        let digest_bytes: [u8; 32] = bytes
            .get(8..40)
            .and_then(|s| s.try_into().ok())
            .ok_or(Error::Corrupt("stored head digest"))?;
        Ok(Some(Head {
            seq: u64::from_le_bytes(seq_bytes),
            digest: Digest(digest_bytes),
        }))
    }

    fn read_all_entries(&self) -> Result<Vec<Entry>> {
        let mut stmt = self
            .conn
            .prepare("SELECT entry_bytes FROM entries ORDER BY seq ASC;")?;
        let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;

        let mut entries = Vec::new();
        for row in rows {
            let bytes = row?;
            // Same canonical-decode gate as the SQL backend: a tampered cache row that is
            // a non-canonical alias is rejected here, not silently loaded.
            let entry = Entry::from_bytes(&bytes).map_err(Error::Crypto)?;
            entries.push(entry);
        }
        Ok(entries)
    }
}

/// The result of loading and verifying the cache.
#[derive(Debug)]
pub enum LoadOutcome {
    /// The cache was empty - first run, or after a clear.
    Empty,
    /// The cache verified. Entries are in ascending order; `head` is the pinned tip.
    Verified {
        /// The verified entries, ascending by seq.
        entries: Vec<Entry>,
        /// The chain head.
        head: Head,
    },
    /// The cache failed verification or decode. The caller should [`Cache::clear`] and
    /// resync from the server. **Not** an error: a bad cache is expected and recoverable.
    Unusable,
}

impl LoadOutcome {
    /// The verified entries, or an empty slice for [`Empty`](LoadOutcome::Empty) and
    /// [`Unusable`](LoadOutcome::Unusable).
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        match self {
            LoadOutcome::Verified { entries, .. } => entries,
            _ => &[],
        }
    }
}
