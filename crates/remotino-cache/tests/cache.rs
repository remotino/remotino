//! Cache behaviour, including the adversarial load path.
//!
//! No external service - the cache is pure local SQLite, bundled, so these always run.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use remotino_cache::cache::LoadOutcome;
use remotino_cache::Cache;
use remotino_crypto::chain::{Entry, EntryBody, Seq};
use remotino_crypto::identity::{Identity, KeyId, PublicIdentity};
use remotino_crypto::Digest;
use std::collections::HashMap;

fn entry(seq: Seq, prev: Digest, id: &Identity) -> Entry {
    Entry::sign(
        EntryBody {
            seq,
            prev,
            timestamp: "2026-07-21T00:00:00Z".to_owned(),
            actor: id.key_id(),
            action: "Test".to_owned(),
            payload: vec![7, 7],
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

fn directory(id: &Identity) -> HashMap<KeyId, PublicIdentity> {
    let mut d = HashMap::new();
    d.insert(id.key_id(), id.public().clone());
    d
}

#[test]
fn append_then_load_verifies_and_returns_entries() {
    let id = Identity::generate().unwrap();
    let dir = directory(&id);
    let mut cache = Cache::open_in_memory().unwrap();

    cache.append_verified(&chain_of(5, &id)).unwrap();

    match cache.load_verified(|k| dir.get(k).cloned()).unwrap() {
        LoadOutcome::Verified { entries, head } => {
            assert_eq!(entries.len(), 5);
            assert_eq!(head.seq, 4);
        }
        other => panic!("expected Verified, got {other:?}"),
    }
    assert_eq!(cache.cursor().unwrap(), Some(4));
}

#[test]
fn empty_cache_loads_as_empty() {
    let id = Identity::generate().unwrap();
    let dir = directory(&id);
    let cache = Cache::open_in_memory().unwrap();
    assert!(matches!(
        cache.load_verified(|k| dir.get(k).cloned()).unwrap(),
        LoadOutcome::Empty
    ));
    assert_eq!(cache.cursor().unwrap(), None);
}

#[test]
fn incremental_append_extends_the_chain() {
    let id = Identity::generate().unwrap();
    let dir = directory(&id);
    let mut cache = Cache::open_in_memory().unwrap();

    let full = chain_of(6, &id);
    cache.append_verified(&full[..3]).unwrap();
    assert_eq!(cache.cursor().unwrap(), Some(2));

    cache.append_verified(&full[3..]).unwrap();
    assert_eq!(cache.cursor().unwrap(), Some(5));

    assert_eq!(
        cache.load_verified(|k| dir.get(k).cloned()).unwrap().entries().len(),
        6
    );
}

#[test]
fn a_tampered_cache_row_is_rejected_not_trusted() {
    // THE security-critical test. A cache is local disk on a machine whose user may not
    // be trusted, so a modified entry must be caught at load, never rendered as if
    // verified. Here we corrupt the stored bytes directly and confirm the loader treats
    // the cache as unusable rather than returning the tampered entry.
    let id = Identity::generate().unwrap();
    let dir = directory(&id);

    let path = std::env::temp_dir().join(format!("remotino-cache-tamper-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&path);
    {
        let mut cache = Cache::open(&path).unwrap();
        cache.append_verified(&chain_of(3, &id)).unwrap();
    }

    // Flip a byte inside a stored entry via a raw SQLite connection.
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        let mut bytes: Vec<u8> = conn
            .query_row("SELECT entry_bytes FROM entries WHERE seq = 1;", [], |r| r.get(0))
            .unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01; // corrupt the signature tail
        conn.execute(
            "UPDATE entries SET entry_bytes = ?1 WHERE seq = 1;",
            rusqlite::params![bytes],
        )
        .unwrap();
    }

    let cache = Cache::open(&path).unwrap();
    let outcome = cache.load_verified(|k| dir.get(k).cloned()).unwrap();
    assert!(
        matches!(outcome, LoadOutcome::Unusable),
        "tampered cache was not rejected: {outcome:?}"
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_cache_signed_by_an_unknown_identity_is_unusable() {
    // Verification resolves signers against the caller's directory. An entry whose signer
    // is not in the directory - e.g. a user since removed, or a forged actor - makes the
    // cache unusable rather than silently trusted.
    let real = Identity::generate().unwrap();
    let mut cache = Cache::open_in_memory().unwrap();
    cache.append_verified(&chain_of(3, &real)).unwrap();

    // Empty directory: the signer resolves to nothing.
    let outcome = cache.load_verified(|_| None).unwrap();
    assert!(matches!(outcome, LoadOutcome::Unusable));
}

#[test]
fn append_rejects_a_gap() {
    let id = Identity::generate().unwrap();
    let mut cache = Cache::open_in_memory().unwrap();
    cache.append_verified(&chain_of(2, &id)).unwrap();

    // seq jumps from 1 to 5.
    let orphan = entry(5, Digest::of(b"nowhere"), &id);
    assert!(cache.append_verified(&[orphan]).is_err());
    // Nothing changed.
    assert_eq!(cache.cursor().unwrap(), Some(1));
}

#[test]
fn clear_empties_the_cache() {
    let id = Identity::generate().unwrap();
    let mut cache = Cache::open_in_memory().unwrap();
    cache.append_verified(&chain_of(4, &id)).unwrap();
    cache.clear().unwrap();
    assert_eq!(cache.cursor().unwrap(), None);
    assert!(cache.stored_head().unwrap().is_none());
}

#[test]
fn stored_head_matches_the_last_entry_and_guards_rollback() {
    let id = Identity::generate().unwrap();
    let entries = chain_of(4, &id);
    let mut cache = Cache::open_in_memory().unwrap();
    cache.append_verified(&entries).unwrap();

    let head = cache.stored_head().unwrap().unwrap();
    assert_eq!(head.seq, 3);
    assert_eq!(head.digest, entries.last().unwrap().digest().unwrap());

    // A server head that moved backwards must trip the rollback alarm.
    let rewound = remotino_crypto::chain::Head {
        seq: 1,
        digest: entries[1].digest().unwrap(),
    };
    assert!(rewound.check_not_rewound(&head).is_err());
}

#[test]
fn persistence_survives_reopen() {
    let id = Identity::generate().unwrap();
    let dir = directory(&id);
    let path = std::env::temp_dir().join(format!("remotino-cache-persist-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&path);

    {
        let mut cache = Cache::open(&path).unwrap();
        cache.append_verified(&chain_of(3, &id)).unwrap();
    }
    {
        let cache = Cache::open(&path).unwrap();
        assert_eq!(cache.cursor().unwrap(), Some(2));
        assert_eq!(
            cache.load_verified(|k| dir.get(k).cloned()).unwrap().entries().len(),
            3
        );
    }
    let _ = std::fs::remove_file(&path);
}
