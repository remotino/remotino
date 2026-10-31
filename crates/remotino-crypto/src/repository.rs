//! Storage abstraction (`DESIGN.md` 3, 8.2).
//!
//! Defined in Phase 1 even though only a file backend is planned, because the shape of
//! this trait is what keeps the SQL Server backend a transport swap rather than a
//! rewrite. Getting it wrong later is expensive; getting it right now is nearly free.
//!
//! # The crypto sits *above* this trait
//!
//! Implementations move opaque bytes. A backend never sees plaintext, which is why moving
//! from SMB to SQL Server changes durability and concurrency but not confidentiality
//! (`DESIGN.md` 8.2).
//!
//! # What the repository checks, and what it cannot
//!
//! `append` enforces the *structural* chain invariants - genesis rules, sequence
//! contiguity, correct `prev` links - because those are checkable without any key
//! material. It does **not** verify signatures: that requires the identity directory,
//! which lives above this trait, and a client must re-verify with
//! [`crate::chain::verify_chain`] regardless, since the store itself is untrusted.
//! Repository-side checks are hygiene that keeps an honest writer from corrupting the
//! log; they are not, and cannot be, the security boundary.
//!
//! # Append-only
//!
//! There is deliberately no `update` or `delete`. Compaction happens through
//! `EpochSealed` (`DESIGN.md` 8.1), which archives entries while retaining a Merkle root -
//! so history stays verifiable from genesis at constant cost. A backend that offered
//! mutation would make the audit chain unenforceable.

use crate::chain::{Entry, Head, Seq};
use crate::{Digest, Error, Result};

/// Append-only storage for the signed audit chain.
///
/// Synchronous by design: the crate is I/O-free and this trait is the seam where I/O
/// enters. An async variant can wrap it where needed; forcing async here would push
/// executor choice into the crypto core.
///
/// # The byte-level storage contract
///
/// [`Entry::from_bytes`] rejects any encoding that is not byte-identical to
/// [`Entry::to_bytes`] of the value it decodes to, so parsed entries and canonical
/// bytes are **one-to-one**. A backend may therefore hold either representation:
///
/// - **Bytes** (a `SqlRepo`): write `Entry::to_bytes` output verbatim into the `body`
///   column and decode with `Entry::from_bytes` on read. If the store returns
///   anything but the exact original bytes - a re-encoding, a normalisation, a
///   trailing pad - the decode fails loudly instead of yielding an entry whose
///   digest no longer matches what was stored.
/// - **Structs** ([`MemoryRepo`]): the bijection makes re-encoding on read produce
///   exactly the bytes that were (or would have been) stored.
///
/// There is no third option to get wrong: `Entry` deliberately does not implement
/// `Deserialize`, so no backend can construct one from bytes while skipping the
/// canonicality check. Never store an entry in any encoding other than
/// `Entry::to_bytes` - it is the only encoding that will decode.
pub trait Repository {
    /// Appends entries atomically.
    ///
    /// Either all are durable or none are. A partial append would leave a chain whose
    /// head does not match its contents.
    ///
    /// Implementations **must** reject a batch that does not extend the current head
    /// contiguously: the first entry must be genesis (`seq == 0`,
    /// `prev == Digest::ZERO`) on an empty repository or `(head.seq + 1, head.digest)`
    /// otherwise, and each subsequent entry must link to its predecessor. An empty
    /// batch is an error - "appended nothing" must not manufacture an `Ok(Head)`.
    /// [`MemoryRepo`] is the executable form of this contract.
    ///
    /// # Errors
    ///
    /// [`Error::ChainIntegrity`] for a batch violating the invariants above; otherwise
    /// implementation-defined (typically I/O failure or a concurrent-append conflict).
    fn append(&mut self, entries: &[Entry]) -> Result<Head>;

    /// Reads entries with sequence greater than `after`, or from genesis if `None`.
    ///
    /// This is the incremental-sync primitive that keeps startup off the network
    /// (`DESIGN.md` 3): a client passes its cached cursor and receives only what is new.
    ///
    /// Entries **must** be returned in ascending `seq` order. `verify_chain` walks the
    /// slice in order, so a backend that returned rows in insertion or index order
    /// would make every read of a valid chain fail verification - or worse, train
    /// callers to sort-and-hope.
    ///
    /// # Errors
    ///
    /// Implementation-defined; typically I/O failure or malformed stored data.
    fn read_from(&self, after: Option<Seq>) -> Result<Vec<Entry>>;

    /// Returns the current head, or `None` for an empty repository.
    ///
    /// Cheap by contract - clients poll it to detect remote changes, so it must not
    /// require reading the whole log.
    ///
    /// # Errors
    ///
    /// Implementation-defined.
    fn head(&self) -> Result<Option<Head>>;
}

/// In-memory reference implementation.
///
/// Public rather than test-only, on purpose: this is the executable specification of
/// the [`Repository`] contract, and the previous, laxer version of it is exactly how a
/// contract gap ships - a `SqlRepo` written against a reference that never checked
/// contiguity or links would have inherited the omission silently
/// (REVIEW-EXTERNAL.md finding 11). New backends should be tested for behavioural
/// equivalence against this type.
#[derive(Debug, Default)]
pub struct MemoryRepo {
    entries: Vec<Entry>,
}

impl MemoryRepo {
    /// An empty repository.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl Repository for MemoryRepo {
    fn append(&mut self, entries: &[Entry]) -> Result<Head> {
        if entries.is_empty() {
            return Err(Error::ChainIntegrity("empty append"));
        }

        // Validate the whole batch against the current head before touching state:
        // an error must leave the repository exactly as it was.
        let mut head = self.head()?;
        for entry in entries {
            match head {
                None => {
                    if entry.body.seq != 0 || entry.body.prev != Digest::ZERO {
                        return Err(Error::ChainIntegrity(
                            "append does not start at genesis on an empty repository",
                        ));
                    }
                }
                Some(h) => {
                    let next_seq = h
                        .seq
                        .checked_add(1)
                        .ok_or(Error::ChainIntegrity("sequence overflow"))?;
                    if entry.body.seq != next_seq {
                        return Err(Error::ChainIntegrity("append leaves a sequence gap"));
                    }
                    if entry.body.prev != h.digest {
                        return Err(Error::ChainIntegrity("append breaks the hash link"));
                    }
                }
            }
            head = Some(Head {
                seq: entry.body.seq,
                digest: entry.digest()?,
            });
        }

        let head = head.ok_or(Error::ChainIntegrity("append produced an empty chain"))?;
        self.entries.extend_from_slice(entries);
        Ok(head)
    }

    fn read_from(&self, after: Option<Seq>) -> Result<Vec<Entry>> {
        // Insertion order is already ascending (append enforces contiguity), so no
        // sort is needed here - but the CONTRACT is ascending seq, not "whatever order
        // the store iterates". A SqlRepo needs an ORDER BY, not luck.
        Ok(match after {
            None => self.entries.clone(),
            Some(seq) => self
                .entries
                .iter()
                .filter(|e| e.body.seq > seq)
                .cloned()
                .collect(),
        })
    }

    fn head(&self) -> Result<Option<Head>> {
        self.entries
            .last()
            .map(|e| {
                Ok(Head {
                    seq: e.body.seq,
                    digest: e.digest()?,
                })
            })
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{Entry, EntryBody};
    use crate::identity::Identity;
    use crate::{Digest, Error};

    fn entry(seq: Seq, prev: Digest, id: &Identity) -> Entry {
        Entry::sign(
            EntryBody {
                seq,
                prev,
                timestamp: "2026-07-21T00:00:00Z".to_owned(),
                actor: id.key_id(),
                action: "Test".to_owned(),
                payload: Vec::new(),
            },
            id,
        )
        .unwrap()
    }

    #[test]
    fn empty_repository_has_no_head() {
        let repo = MemoryRepo::default();
        assert!(repo.head().unwrap().is_none());
    }

    #[test]
    fn append_then_read_roundtrips() {
        let id = Identity::generate().unwrap();
        let mut repo = MemoryRepo::default();

        let e0 = entry(0, Digest::ZERO, &id);
        let d0 = e0.digest().unwrap();
        let e1 = entry(1, d0, &id);

        repo.append(&[e0, e1]).unwrap();
        assert_eq!(repo.read_from(None).unwrap().len(), 2);
        assert_eq!(repo.head().unwrap().unwrap().seq, 1);
    }

    #[test]
    fn incremental_read_returns_only_what_is_new() {
        // The behaviour the whole startup-performance argument rests on.
        let id = Identity::generate().unwrap();
        let mut repo = MemoryRepo::default();

        let e0 = entry(0, Digest::ZERO, &id);
        let d0 = e0.digest().unwrap();
        let e1 = entry(1, d0, &id);
        repo.append(&[e0, e1]).unwrap();

        let fresh = repo.read_from(Some(0)).unwrap();
        assert_eq!(fresh.len(), 1);
        assert_eq!(fresh.first().unwrap().body.seq, 1);
    }

    #[test]
    fn stored_entries_still_verify_after_a_roundtrip() {
        // Guards against a backend that mangles bytes: signatures must survive storage.
        let id = Identity::generate().unwrap();
        let mut repo = MemoryRepo::default();
        repo.append(&[entry(0, Digest::ZERO, &id)]).unwrap();

        let read = repo.read_from(None).unwrap();
        read.first().unwrap().verify(id.public()).unwrap();
    }

    // ------------------------------------------------------------------
    // Contract enforcement (REVIEW-EXTERNAL.md finding 11). These pin the behaviours
    // a SqlRepo must reproduce; before them, the reference accepted anything.
    // ------------------------------------------------------------------

    #[test]
    fn empty_append_cannot_manufacture_a_head() {
        let mut repo = MemoryRepo::default();
        assert!(repo.append(&[]).is_err());
    }

    #[test]
    fn append_that_skips_genesis_is_rejected() {
        let id = Identity::generate().unwrap();
        let mut repo = MemoryRepo::default();
        // seq 5 out of nowhere: a truncated-then-continued log in the making.
        assert!(matches!(
            repo.append(&[entry(5, Digest::ZERO, &id)]),
            Err(Error::ChainIntegrity(_))
        ));
        assert!(repo.head().unwrap().is_none(), "failed append must not commit");
    }

    #[test]
    fn append_with_a_sequence_gap_is_rejected() {
        let id = Identity::generate().unwrap();
        let mut repo = MemoryRepo::default();
        let e0 = entry(0, Digest::ZERO, &id);
        let d0 = e0.digest().unwrap();
        repo.append(&[e0]).unwrap();

        assert!(matches!(
            repo.append(&[entry(2, d0, &id)]),
            Err(Error::ChainIntegrity(_))
        ));
        assert_eq!(repo.head().unwrap().unwrap().seq, 0);
    }

    #[test]
    fn append_with_a_broken_link_is_rejected() {
        let id = Identity::generate().unwrap();
        let mut repo = MemoryRepo::default();
        repo.append(&[entry(0, Digest::ZERO, &id)]).unwrap();

        // Right seq, wrong prev: this entry claims a different history.
        assert!(matches!(
            repo.append(&[entry(1, Digest::of(b"someone else's history"), &id)]),
            Err(Error::ChainIntegrity(_))
        ));
    }

    #[test]
    fn failed_batch_commits_nothing() {
        // Atomicity: a batch that goes bad half-way must leave no partial state.
        let id = Identity::generate().unwrap();
        let mut repo = MemoryRepo::default();
        let e0 = entry(0, Digest::ZERO, &id);
        let d0 = e0.digest().unwrap();
        let bad = entry(7, d0, &id); // valid link target, wrong seq

        assert!(repo.append(&[e0, bad]).is_err());
        assert!(repo.head().unwrap().is_none());
        assert!(repo.read_from(None).unwrap().is_empty());
    }

    #[test]
    fn read_from_returns_ascending_seq() {
        let id = Identity::generate().unwrap();
        let mut repo = MemoryRepo::default();
        let e0 = entry(0, Digest::ZERO, &id);
        let d0 = e0.digest().unwrap();
        let e1 = entry(1, d0, &id);
        let d1 = e1.digest().unwrap();
        let e2 = entry(2, d1, &id);
        repo.append(&[e0, e1, e2]).unwrap();

        let seqs: Vec<Seq> = repo.read_from(None).unwrap().iter().map(|e| e.body.seq).collect();
        assert_eq!(seqs, vec![0, 1, 2]);
    }
}
