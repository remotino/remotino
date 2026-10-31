//! The signed, hash-chained audit log (`DESIGN.md` 5).
//!
//! Not a blockchain. Consensus solves mutually distrusting parties with no shared
//! authority, which is not the situation here and would cost the speed the project exists
//! to gain. This is what Git and Certificate Transparency use: each entry commits to its
//! predecessor's hash and is signed by its author.
//!
//! # What this gives, and what it does not
//!
//! Editing any historical entry breaks every subsequent link, and no entry can be forged
//! without a private key. But a hash chain detects **mutation**, not **truncation**:
//! whoever can write to the store can delete the newest entries and leave a chain that is
//! still internally valid.
//!
//! Mitigations, per `DESIGN.md` 5:
//!
//! 1. Clients pin the highest `(seq, head)` they have seen - a head that moves backwards
//!    is an unambiguous alarm. See [`Head`].
//! 2. Append-only storage permissions, which prevent rather than detect.
//!
//! Truncation defence therefore lives partly outside this module; it cannot be solved by
//! hashing alone, and pretending otherwise would be the dangerous kind of tidy.
//!
//! # Canonical bytes: the storage contract
//!
//! CBOR admits many encodings of the same value (reordered map keys, non-minimal
//! integers, indefinite lengths). Digests and signatures here are computed over *the*
//! canonical encoding - the one [`Entry::to_bytes`] produces - so if arbitrary
//! encodings were accepted on decode, two byte-distinct stored entries would share a
//! digest and the chain would no longer pin bytes, only meanings (REVIEW.md).
//!
//! The fix fails closed: **non-canonical input is rejected at decode**. [`Entry`]
//! deliberately does not implement `Deserialize`; the only way to obtain one from
//! stored bytes is [`Entry::from_bytes`], which refuses any input that is not
//! byte-identical to the canonical encoding of the value it decodes to. Struct and
//! canonical bytes are therefore one-to-one, and a repository may store either form -
//! exact bytes (the SQL `body` column) or parsed entries ([`crate::repository::MemoryRepo`]) -
//! without the two ever disagreeing. See [`crate::repository::Repository`] for the
//! backend-facing statement of this contract.

use serde::{Deserialize, Serialize};

use crate::identity::{Identity, KeyId, PublicIdentity};
use crate::{Digest, Error, Result};

/// Monotonic position of an entry in the log.
pub type Seq = u64;

/// An audit entry, before signing.
///
/// No `Deserialize` on purpose: entries come off storage only through
/// [`Entry::from_bytes`], which enforces canonical encoding (see the module docs).
#[derive(Debug, Clone, Serialize)]
pub struct EntryBody {
    /// Position in the chain. The genesis entry is 0.
    pub seq: Seq,
    /// Digest of the previous entry, or [`Digest::ZERO`] for genesis.
    pub prev: Digest,
    /// RFC3339 UTC timestamp, informational only.
    ///
    /// Deliberately **not** trusted for ordering: clocks on a shared network drift and
    /// can be set deliberately. `seq` and `prev` establish order; this is for humans.
    pub timestamp: String,
    /// Identity that authored the entry.
    pub actor: KeyId,
    /// What happened, e.g. `EntryUpdated`, `AclGranted`, `EscrowQuorumChanged`.
    pub action: String,
    /// Encrypted or opaque payload. Secrets are never recorded here (`DESIGN.md` 5).
    pub payload: Vec<u8>,
}

/// A signed audit entry.
///
/// No `Deserialize` on purpose: the only path from stored bytes to an `Entry` is
/// [`Entry::from_bytes`], which rejects non-canonical encodings. Without that
/// restriction, any caller could `ciborium::from_reader` a byte-mangled alias of an
/// entry and compute the honest entry's digest for it (see the module docs).
#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    /// The signed content.
    pub body: EntryBody,
    /// Ed25519 signature over the canonical encoding of `body`.
    ///
    /// `serde` only implements its traits for arrays up to 32 elements, hence the
    /// `BigArray` helper. Kept as a fixed `[u8; 64]` rather than a `Vec<u8>` so a
    /// wrong-length signature is rejected at decode time instead of at verification.
    #[serde(with = "serde_big_array::BigArray")]
    pub signature: [u8; 64],
}

/// Wire form of [`EntryBody`]: same fields, no invariants, `Deserialize` only.
///
/// Exists so deserialisation can funnel through [`Entry::from_bytes`], the same
/// pattern [`crate::identity::PublicIdentity`] uses. Field names and order must stay
/// identical to `EntryBody` or the canonical encoding silently changes.
#[derive(Deserialize)]
struct EntryBodyWire {
    seq: Seq,
    prev: Digest,
    timestamp: String,
    actor: KeyId,
    action: String,
    payload: Vec<u8>,
}

/// Wire form of [`Entry`]. See [`EntryBodyWire`].
#[derive(Deserialize)]
struct EntryWire {
    body: EntryBodyWire,
    #[serde(with = "serde_big_array::BigArray")]
    signature: [u8; 64],
}

impl From<EntryWire> for Entry {
    fn from(wire: EntryWire) -> Self {
        Self {
            body: EntryBody {
                seq: wire.body.seq,
                prev: wire.body.prev,
                timestamp: wire.body.timestamp,
                actor: wire.body.actor,
                action: wire.body.action,
                payload: wire.body.payload,
            },
            signature: wire.signature,
        }
    }
}

impl Entry {
    /// Signs `body` with `identity`.
    ///
    /// # Errors
    ///
    /// [`Error::Encoding`] if the body cannot be canonically encoded.
    /// [`Error::ChainIntegrity`] if `body.actor` is not this identity - signing on behalf
    /// of someone else would produce an entry that can never verify.
    pub fn sign(body: EntryBody, identity: &Identity) -> Result<Self> {
        if body.actor != identity.key_id() {
            return Err(Error::ChainIntegrity("actor does not match signing identity"));
        }
        let bytes = canonical(&body)?;
        Ok(Self {
            signature: identity.sign(&bytes),
            body,
        })
    }

    /// This entry's digest, which the next entry commits to.
    ///
    /// Covers the signature as well as the body, so the link pins *which* signature was
    /// accepted, not merely the content. Domain-tagged so an entry digest can never
    /// collide with the untagged digest of some other object that shares its bytes -
    /// the crate's own convention, previously broken at the one place it protects the
    /// chain (REVIEW-EXTERNAL.md finding 12).
    ///
    /// # Errors
    ///
    /// [`Error::Encoding`] if the entry cannot be canonically encoded.
    pub fn digest(&self) -> Result<Digest> {
        Ok(Digest::tagged(b"remotino/v1/chain-entry", &canonical(self)?))
    }

    /// Encodes this entry as its canonical bytes - the only form a repository stores.
    ///
    /// A SQL backend writes exactly these bytes into its `body` column, verbatim.
    /// [`Entry::from_bytes`] round-trips them and refuses anything else, so "store the
    /// exact original bytes" is not a convention the backend must remember - it is the
    /// only thing that will decode.
    ///
    /// # Errors
    ///
    /// [`Error::Encoding`] if the entry cannot be canonically encoded.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        canonical(self)
    }

    /// Decodes an entry from stored bytes, rejecting any non-canonical encoding.
    ///
    /// This is the **only** way to obtain an [`Entry`] from bytes - the type has no
    /// `Deserialize` impl, so no code path can skip this check. The input must be
    /// byte-identical to the canonical encoding of the value it decodes to; reordered
    /// map keys, non-minimally-encoded integers, indefinite-length items and trailing
    /// bytes are all refused. That makes entry digests injective over stored bytes:
    /// two byte-distinct blobs that both decode can never share a digest, because
    /// neither would survive this check unless it *is* the canonical form
    /// (REVIEW.md, "CBOR is not canonical").
    ///
    /// # Errors
    ///
    /// [`Error::Encoding`] if the bytes do not decode, or decode but are not the
    /// canonical encoding.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let wire: EntryWire =
            ciborium::from_reader(bytes).map_err(|_| Error::Encoding("cbor decode"))?;
        let entry = Self::from(wire);
        // The received bytes must BE the canonical encoding of what they decoded to.
        // ciborium's encoder is deterministic (definite lengths, minimal integers,
        // declaration-order map keys), so this comparison is the canonicality check.
        if canonical(&entry)? != bytes {
            return Err(Error::Encoding("non-canonical CBOR encoding of an entry"));
        }
        Ok(entry)
    }

    /// Verifies the signature against `author`.
    ///
    /// # Errors
    ///
    /// [`Error::ChainIntegrity`] if `author` is not the claimed actor, [`Error::Signature`]
    /// if the signature does not verify.
    pub fn verify(&self, author: &PublicIdentity) -> Result<()> {
        if author.key_id() != self.body.actor {
            return Err(Error::ChainIntegrity("author is not the claimed actor"));
        }
        let bytes = canonical(&self.body)?;
        author.verify(&bytes, &self.signature)
    }
}

/// The furthest point of a chain a client has observed.
///
/// Persisted locally so a head that moves *backwards* is detectable. That is the cheap
/// half of the truncation defence, and it catches the realistic case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Head {
    /// Sequence number of the last entry.
    pub seq: Seq,
    /// Digest of the last entry.
    pub digest: Digest,
}

impl Head {
    /// Checks that `self` has not been *rewound* relative to `previous`: the sequence
    /// has not moved backwards, and the digest has not changed at the same sequence.
    ///
    /// This is the cheap, entry-free half of the truncation defence - suitable for
    /// polling a repository's head without reading the log.
    ///
    /// # What this deliberately does NOT check
    ///
    /// It does **not** prove that `self` descends from `previous`. An attacker who
    /// truncates the log after the pinned entry and appends new entries produces a
    /// *fork* whose head has a higher `seq` - and a higher `seq` with a different
    /// digest looks exactly like honest progress to a seq-and-digest comparison. No
    /// check on two `(seq, digest)` pairs alone can tell those apart; descent is a
    /// property of the entries in between.
    ///
    /// The sound check is [`verify_chain`]`(new_entries, Some(pinned), ..)`: it walks
    /// the hash links from the pinned head, so a forked suffix fails with a broken
    /// link at the first divergent entry. Call this function for the cheap alarm,
    /// then `verify_chain` from the pin before trusting (or re-pinning) anything.
    ///
    /// This function was previously named `check_advance`, which read as if it proved
    /// the head had validly advanced. It cannot, so it is now named for exactly what
    /// it checks (REVIEW.md, "`Head::check_advance` does not detect forks").
    ///
    /// # Errors
    ///
    /// [`Error::ChainIntegrity`] if the head has moved backwards, or has stayed at the
    /// same sequence while changing digest - which means history was rewritten.
    pub fn check_not_rewound(&self, previous: &Head) -> Result<()> {
        if self.seq < previous.seq {
            return Err(Error::ChainIntegrity("head moved backwards - possible truncation"));
        }
        if self.seq == previous.seq && self.digest != previous.digest {
            return Err(Error::ChainIntegrity("head digest changed at same seq - history rewritten"));
        }
        Ok(())
    }
}

/// Verifies a contiguous run of entries.
///
/// `resolve` maps an actor to their public identity; it returns `None` for an unknown
/// author, which is itself a failure - an entry signed by someone not enrolled must not
/// be accepted merely because its signature is well-formed.
///
/// Pass `expected_prev` to continue from a known point, or `None` to require that the
/// slice begins at genesis. Continuing from a pinned head is also the **fork check**:
/// the first entry must link to the pinned digest, so a store that truncated the log
/// after the pin and grew a different history fails here even though its head has a
/// higher `seq`. [`Head::check_not_rewound`] alone cannot see that case.
///
/// Returns the verified head. Verifying zero entries against no prior head is an
/// **error**, not an empty success: `Ok` from this function must always mean "there is
/// a verified head", because an `Ok(None)` that reads as success is exactly the shape
/// of result callers stop checking (REVIEW-EXTERNAL.md finding 15). An empty repository
/// has nothing to verify - callers should not be calling this on one. An empty *delta*
/// against a known head is fine and returns that head unchanged.
///
/// # Errors
///
/// [`Error::ChainIntegrity`] on a broken link, a sequence gap, an unknown author, or an
/// empty slice with no prior head; [`Error::Signature`] on a bad signature.
pub fn verify_chain<F>(
    entries: &[Entry],
    expected_prev: Option<Head>,
    mut resolve: F,
) -> Result<Head>
where
    F: FnMut(&KeyId) -> Option<PublicIdentity>,
{
    let mut expected = expected_prev;

    for entry in entries {
        match expected {
            None => {
                if entry.body.seq != 0 || entry.body.prev != Digest::ZERO {
                    return Err(Error::ChainIntegrity("chain does not start at genesis"));
                }
            }
            Some(head) => {
                let next_seq = head
                    .seq
                    .checked_add(1)
                    .ok_or(Error::ChainIntegrity("sequence overflow"))?;
                if entry.body.seq != next_seq {
                    return Err(Error::ChainIntegrity("sequence gap"));
                }
                if entry.body.prev != head.digest {
                    return Err(Error::ChainIntegrity("broken hash link"));
                }
            }
        }

        let author = resolve(&entry.body.actor)
            .ok_or(Error::ChainIntegrity("entry signed by unknown identity"))?;
        entry.verify(&author)?;

        expected = Some(Head {
            seq: entry.body.seq,
            digest: entry.digest()?,
        });
    }

    expected.ok_or(Error::ChainIntegrity(
        "nothing to verify: no entries and no prior head",
    ))
}

/// Canonical encoding used for hashing and signing.
///
/// Everything that is hashed or signed goes through this one function. If signing and
/// verification ever encoded differently, every signature would silently fail to verify -
/// or worse, verify something other than what was intended.
fn canonical<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).map_err(|_| Error::Encoding("cbor encode"))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn body(seq: Seq, prev: Digest, actor: KeyId, action: &str) -> EntryBody {
        EntryBody {
            seq,
            prev,
            timestamp: "2026-07-21T00:00:00Z".to_owned(),
            actor,
            action: action.to_owned(),
            payload: Vec::new(),
        }
    }

    struct Fixture {
        alice: Identity,
        directory: HashMap<KeyId, PublicIdentity>,
    }

    impl Fixture {
        fn new() -> Self {
            let alice = Identity::generate().unwrap();
            let mut directory = HashMap::new();
            directory.insert(alice.key_id(), alice.public().clone());
            Self { alice, directory }
        }

        fn resolver(&self) -> impl FnMut(&KeyId) -> Option<PublicIdentity> + '_ {
            move |id: &KeyId| self.directory.get(id).cloned()
        }

        fn chain(&self, len: u64) -> Vec<Entry> {
            let mut entries = Vec::new();
            let mut prev = Digest::ZERO;
            for seq in 0..len {
                let e = Entry::sign(body(seq, prev, self.alice.key_id(), "Test"), &self.alice)
                    .unwrap();
                prev = e.digest().unwrap();
                entries.push(e);
            }
            entries
        }
    }

    #[test]
    fn valid_chain_verifies() {
        let f = Fixture::new();
        let entries = f.chain(5);
        let head = verify_chain(&entries, None, f.resolver()).unwrap();
        assert_eq!(head.seq, 4);
    }

    #[test]
    fn mutating_a_middle_entry_breaks_the_chain() {
        // The core guarantee: history cannot be edited without detection.
        let f = Fixture::new();
        let mut entries = f.chain(5);
        if let Some(e) = entries.get_mut(2) {
            e.body.action = "Tampered".to_owned();
        }
        assert!(verify_chain(&entries, None, f.resolver()).is_err());
    }

    #[test]
    fn reordering_breaks_the_chain() {
        let f = Fixture::new();
        let mut entries = f.chain(5);
        entries.swap(1, 3);
        assert!(verify_chain(&entries, None, f.resolver()).is_err());
    }

    #[test]
    fn removing_an_entry_breaks_the_chain() {
        let f = Fixture::new();
        let mut entries = f.chain(5);
        entries.remove(2);
        assert!(verify_chain(&entries, None, f.resolver()).is_err());
    }

    #[test]
    fn unknown_author_is_rejected() {
        // A signature being well-formed is not enough; the author must be enrolled.
        let f = Fixture::new();
        let outsider = Identity::generate().unwrap();
        let entry = Entry::sign(
            body(0, Digest::ZERO, outsider.key_id(), "Sneaky"),
            &outsider,
        )
        .unwrap();
        assert!(verify_chain(&[entry], None, f.resolver()).is_err());
    }

    #[test]
    fn forged_identity_cannot_impersonate_in_chain() {
        // The end-to-end form of REVIEW.md finding 1. When key_id hashed only the
        // wrapping key, Mallory could publish a PublicIdentity carrying Alice's wrapping
        // key and his own verifying key. It computed to Alice's KeyId, so the actor check
        // passed and his signature verified - audit entries attributable to Alice.
        let alice = Identity::generate().unwrap();
        let mallory = Identity::generate().unwrap();

        let forged = PublicIdentity {
            verifying: mallory.public().verifying,
            wrapping: alice.public().wrapping,
        };
        assert_ne!(
            forged.key_id(),
            alice.key_id(),
            "forged identity must not collide with Alice's id"
        );

        // Mallory signs an entry claiming to be Alice.
        let mut entry = Entry::sign(
            body(0, Digest::ZERO, mallory.key_id(), "AclGranted"),
            &mallory,
        )
        .unwrap();
        entry.body.actor = alice.key_id();

        // Verified against the real Alice: signature is Mallory's, so it fails.
        assert!(entry.verify(alice.public()).is_err());
        // Verified against the forged identity: the actor check rejects it.
        assert!(entry.verify(&forged).is_err());
    }

    #[test]
    fn cannot_sign_as_someone_else() {
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();
        let result = Entry::sign(body(0, Digest::ZERO, b.key_id(), "Forged"), &a);
        assert!(result.is_err());
    }

    #[test]
    fn truncation_is_not_detected_by_the_chain_alone() {
        // Documents the known limitation rather than papering over it: a truncated chain
        // is still internally valid, which is exactly why Head pinning exists.
        let f = Fixture::new();
        let full = f.chain(5);
        let truncated = full.get(..3).unwrap().to_vec();
        assert!(verify_chain(&truncated, None, f.resolver()).is_ok());
    }

    #[test]
    fn head_pinning_catches_truncation() {
        let f = Fixture::new();
        let full = f.chain(5);
        let before = verify_chain(&full, None, f.resolver()).unwrap();

        let truncated = full.get(..3).unwrap().to_vec();
        let after = verify_chain(&truncated, None, f.resolver()).unwrap();

        assert!(after.check_not_rewound(&before).is_err());
    }

    #[test]
    fn head_rewrite_at_same_seq_is_caught() {
        let f = Fixture::new();
        let a = verify_chain(&f.chain(3), None, f.resolver()).unwrap();
        let b = Head {
            seq: a.seq,
            digest: Digest::of(b"different"),
        };
        assert!(b.check_not_rewound(&a).is_err());
    }

    #[test]
    fn incremental_verification_continues_from_a_head() {
        let f = Fixture::new();
        let entries = f.chain(6);
        let first = entries.get(..3).unwrap();
        let rest = entries.get(3..).unwrap();

        let head = verify_chain(first, None, f.resolver()).unwrap();
        let final_head = verify_chain(rest, Some(head), f.resolver()).unwrap();
        assert_eq!(final_head.seq, 5);
    }

    #[test]
    fn verifying_nothing_is_not_success() {
        // REVIEW-EXTERNAL.md finding 15: the old Ok(None) on an empty slice read as
        // "chain verified" to any caller not scrutinising the Option. No entries and no
        // prior head means nothing was verified, and that must be an error.
        let f = Fixture::new();
        assert!(verify_chain(&[], None, f.resolver()).is_err());
    }

    #[test]
    fn empty_delta_against_a_known_head_returns_that_head() {
        let f = Fixture::new();
        let head = verify_chain(&f.chain(3), None, f.resolver()).unwrap();
        let same = verify_chain(&[], Some(head), f.resolver()).unwrap();
        assert_eq!(same, head);
    }

    #[test]
    fn fork_with_higher_seq_is_invisible_to_head_comparison_but_caught_by_verify_chain() {
        // REVIEW.md, "check_advance does not detect forks". An enrolled attacker with
        // store write access truncates the log after seq 1 and grows a different
        // history that ends BEYOND the pinned seq. Two (seq, digest) pairs cannot
        // distinguish that from honest progress; only walking the links from the pin
        // can.
        let f = Fixture::new();
        let honest = f.chain(4); // seqs 0..=3
        let pinned = verify_chain(&honest, None, f.resolver()).unwrap();

        // The fork: keep entries 0 and 1, rewrite from seq 2, and append through seq 4.
        let mut fork: Vec<Entry> = honest.get(..2).unwrap().to_vec();
        let mut prev = fork.last().unwrap().digest().unwrap();
        for seq in 2..5 {
            let e = Entry::sign(body(seq, prev, f.alice.key_id(), "Forked"), &f.alice).unwrap();
            prev = e.digest().unwrap();
            fork.push(e);
        }

        // The fork is internally valid and its head outruns the pin...
        let fork_head = verify_chain(&fork, None, f.resolver()).unwrap();
        assert!(fork_head.seq > pinned.seq);
        // ...so the cheap entry-free check passes, BY DESIGN - this is the gap the
        // rename documents, not a bug being tolerated.
        assert!(fork_head.check_not_rewound(&pinned).is_ok());

        // The sound check: verify the delta from the pinned head. The first entry
        // past the pin links to the fork's digest at seq 3, not the pinned one.
        let delta: Vec<Entry> = fork
            .iter()
            .filter(|e| e.body.seq > pinned.seq)
            .cloned()
            .collect();
        assert!(matches!(
            verify_chain(&delta, Some(pinned), f.resolver()),
            Err(Error::ChainIntegrity(_))
        ));
    }

    // ------------------------------------------------------------------
    // Canonical-encoding enforcement (REVIEW.md, "CBOR is not canonical"). Each test
    // hand-crafts non-canonical CBOR bytes and feeds them through the decode path -
    // the way an attacker with store write access would - rather than mutating a
    // struct and re-encoding it. Tests are named for the attack they foreclose.
    // ------------------------------------------------------------------

    #[test]
    fn canonical_bytes_roundtrip_through_from_bytes() {
        // The validation must not reject what honest encoding produces - this pair is
        // the storage contract a SqlRepo lives by.
        let f = Fixture::new();
        let entry = f.chain(1).remove(0);
        let bytes = entry.to_bytes().unwrap();
        let back = Entry::from_bytes(&bytes).unwrap();
        assert_eq!(back.digest().unwrap(), entry.digest().unwrap());
        assert_eq!(back.to_bytes().unwrap(), bytes);
    }

    #[test]
    fn reordered_map_keys_cannot_mint_a_second_encoding_of_an_entry() {
        // CBOR maps carry no key order, so serde happily decodes {prev, seq, ...} into
        // the same EntryBody as {seq, prev, ...}. Before this check, both byte
        // sequences produced the same digest - the stored bytes were not determined
        // by the hash. Build the alias through generic CBOR, from the bytes up.
        let f = Fixture::new();
        let entry = f.chain(1).remove(0);
        let bytes = entry.to_bytes().unwrap();

        let mut value: ciborium::Value = ciborium::from_reader(bytes.as_slice()).unwrap();
        {
            let ciborium::Value::Map(top) = &mut value else {
                panic!("entry must encode as a map")
            };
            let (_, body_value) = top.first_mut().unwrap();
            let ciborium::Value::Map(body) = body_value else {
                panic!("body must encode as a map")
            };
            body.swap(0, 1); // seq and prev trade places
        }
        let mut aliased = Vec::new();
        ciborium::into_writer(&value, &mut aliased).unwrap();
        assert_ne!(aliased, bytes, "the alias must actually differ in bytes");

        // The attack is real: a permissive decode accepts the alias and yields a
        // value whose digest EQUALS the honest entry's - two byte sequences, one hash.
        let permissive: EntryWire = ciborium::from_reader(aliased.as_slice()).unwrap();
        assert_eq!(
            Entry::from(permissive).digest().unwrap(),
            entry.digest().unwrap()
        );

        // And the decode path forecloses it.
        assert!(matches!(
            Entry::from_bytes(&aliased),
            Err(Error::Encoding(_))
        ));
    }

    #[test]
    fn nonminimal_integer_encoding_of_an_entry_is_rejected() {
        // seq = 0 canonically encodes as the single byte 0x00; CBOR also allows
        // 0x18 0x00 (uint8), 0x19 0x00 0x00 (uint16), and so on. Same entry, longer
        // bytes, same digest under a re-encoding hash. Patch the raw bytes directly:
        // the map key "seq" (0x63 's' 'e' 'q') followed by 0x00.
        let f = Fixture::new();
        let entry = f.chain(1).remove(0);
        let bytes = entry.to_bytes().unwrap();

        let needle = [0x63, b's', b'e', b'q', 0x00];
        let pos = bytes
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("genesis entry must contain seq = 0");
        let mut aliased = bytes.clone();
        // Replace the 1-byte 0x00 with the 2-byte non-minimal uint8 form 0x18 0x00.
        aliased.splice(pos + 4..pos + 5, [0x18, 0x00]);

        // Decodes to the identical entry under a permissive decode...
        let permissive: EntryWire = ciborium::from_reader(aliased.as_slice()).unwrap();
        assert_eq!(
            Entry::from(permissive).digest().unwrap(),
            entry.digest().unwrap()
        );
        // ...and is refused by the real one.
        assert!(matches!(
            Entry::from_bytes(&aliased),
            Err(Error::Encoding(_))
        ));
    }

    #[test]
    fn indefinite_length_encoding_of_an_entry_is_rejected() {
        // A definite-length map (0xa2: map of 2) rewritten as an indefinite-length
        // map (0xbf ... 0xff): same decoded value, different bytes.
        let f = Fixture::new();
        let entry = f.chain(1).remove(0);
        let bytes = entry.to_bytes().unwrap();
        assert_eq!(*bytes.first().unwrap(), 0xa2, "entry must encode as a 2-entry map");

        let mut aliased = bytes.clone();
        aliased[0] = 0xbf;
        aliased.push(0xff);
        assert!(matches!(
            Entry::from_bytes(&aliased),
            Err(Error::Encoding(_))
        ));
    }

    #[test]
    fn trailing_bytes_after_an_entry_are_rejected() {
        // Trailing garbage would let unbounded many byte sequences share one digest.
        let f = Fixture::new();
        let entry = f.chain(1).remove(0);
        let mut padded = entry.to_bytes().unwrap();
        padded.push(0x00);
        assert!(matches!(
            Entry::from_bytes(&padded),
            Err(Error::Encoding(_))
        ));
    }
}
