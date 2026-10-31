//! Integration tests against a real SQL Server instance.
//!
//! **Skipped unless `REMOTINO_TEST_SQL` is set**, because a machine without SQL Server
//! should not fail the suite. Set it to a database name to run:
//!
//! ```powershell
//! $env:REMOTINO_TEST_SQL = "Remotino_Dev"
//! cargo test -p remotino-sql
//! ```
//!
//! These tests are destructive - they truncate `dbo.Events`. Point them at a scratch
//! database, never a real one.
//!
//! # Why these exist
//!
//! `MemoryRepo` is the executable contract, but a contract nobody checks the other
//! implementation against is a wish. Everything here asserts that `SqlRepo` behaves
//! identically to `MemoryRepo` on the same inputs - including the failure cases, which
//! is where backends usually diverge.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use remotino_crypto::chain::{self, Entry, EntryBody, Head, Seq};
use remotino_crypto::identity::{Identity, KeyId, PublicIdentity};
use remotino_crypto::repository::{MemoryRepo, Repository};
use remotino_crypto::Digest;
use remotino_sql::{SqlConfig, SqlRepo};
use std::collections::HashMap;

/// Serialises the whole file against one shared database.
///
/// Every test truncates `dbo.Events` and then asserts on its own rows, so running them
/// concurrently means deleting each other's data mid-assertion. That is a harness
/// problem, not a product one - but it produced a convincing "append leaves a sequence
/// gap" failure, so it is worth naming rather than papering over with `--test-threads=1`
/// in some CI invocation nobody reads.
///
/// A mutex rather than the `serial_test` crate: no dependency, and the reason lives here
/// next to the thing it protects.
static DB_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Returns a connected repo plus the lock guard, or `None` if the environment opts out.
///
/// The guard must stay alive for the test body; dropping it early re-opens the race.
fn repo() -> Option<(SqlRepo, std::sync::MutexGuard<'static, ()>)> {
    let db = std::env::var("REMOTINO_TEST_SQL").ok()?;
    let guard = DB_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut repo = SqlRepo::connect_and_migrate(&SqlConfig::local_dev(&db))
        .expect("connect to the test database");
    repo.truncate_for_tests().expect("clear previous rows");
    Some((repo, guard))
}

macro_rules! sql_repo {
    () => {
        match repo() {
            // `_guard` is bound, not discarded with `_`, so it lives to the end of the
            // test rather than being dropped immediately.
            Some((r, _guard)) => (r, _guard),
            None => {
                eprintln!("skipping: REMOTINO_TEST_SQL not set");
                return;
            }
        }
    };
}

fn entry(seq: Seq, prev: Digest, id: &Identity, action: &str) -> Entry {
    Entry::sign(
        EntryBody {
            seq,
            prev,
            timestamp: "2026-07-21T00:00:00Z".to_owned(),
            actor: id.key_id(),
            action: action.to_owned(),
            payload: vec![1, 2, 3],
        },
        id,
    )
    .unwrap()
}

/// Builds a valid chain of `len` entries.
fn chain_of(len: u64, id: &Identity) -> Vec<Entry> {
    let mut out = Vec::new();
    let mut prev = Digest::ZERO;
    for seq in 0..len {
        let e = entry(seq, prev, id, "Test");
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
fn append_and_read_roundtrips_through_real_sql() {
    let (mut repo, _guard) = sql_repo!();
    let id = Identity::generate().unwrap();
    let entries = chain_of(5, &id);

    let head = repo.append(&entries).unwrap();
    assert_eq!(head.seq, 4);

    let read = repo.read_from(None).unwrap();
    assert_eq!(read.len(), 5);
    assert_eq!(repo.head().unwrap().unwrap(), head);
}

#[test]
fn stored_chain_still_verifies_after_a_database_roundtrip() {
    // The point of the whole storage contract: bytes that go into SQL Server and come
    // back must still satisfy verify_chain. A backend that re-encoded, reordered, or
    // truncated anything would fail here.
    let (mut repo, _guard) = sql_repo!();
    let id = Identity::generate().unwrap();
    let dir = directory(&id);

    repo.append(&chain_of(4, &id)).unwrap();
    let read = repo.read_from(None).unwrap();

    let head = chain::verify_chain(&read, None, |k| dir.get(k).cloned()).unwrap();
    assert_eq!(head.seq, 3);
}

#[test]
fn incremental_read_returns_only_new_entries() {
    let (mut repo, _guard) = sql_repo!();
    let id = Identity::generate().unwrap();
    repo.append(&chain_of(6, &id)).unwrap();

    let fresh = repo.read_from(Some(3)).unwrap();
    assert_eq!(fresh.len(), 2);
    assert_eq!(fresh.first().unwrap().body.seq, 4);
}

#[test]
fn sql_and_memory_agree_on_the_same_inputs() {
    // MemoryRepo is the documented contract; this asserts SqlRepo is not merely
    // plausible but identical, on success and on every rejection.
    let (mut sql, _guard) = sql_repo!();
    let mut mem = MemoryRepo::new();
    let id = Identity::generate().unwrap();
    let entries = chain_of(3, &id);

    let sql_head = sql.append(&entries).unwrap();
    let mem_head = mem.append(&entries).unwrap();
    assert_eq!(sql_head, mem_head);

    assert_eq!(
        sql.read_from(None).unwrap().len(),
        mem.read_from(None).unwrap().len()
    );

    // Rejections must match too.
    let orphan = entry(99, Digest::of(b"nowhere"), &id, "Orphan");
    assert!(sql.append(std::slice::from_ref(&orphan)).is_err());
    assert!(mem.append(&[orphan]).is_err());

    assert!(sql.append(&[]).is_err());
    assert!(mem.append(&[]).is_err());
}

#[test]
fn a_gap_in_the_batch_is_rejected_and_nothing_lands() {
    // Atomicity: a batch that fails validation must leave the store untouched. Checking
    // the head afterwards is the part that would catch a backend inserting row-by-row
    // before noticing the problem.
    let (mut repo, _guard) = sql_repo!();
    let id = Identity::generate().unwrap();
    repo.append(&chain_of(2, &id)).unwrap();
    let before = repo.head().unwrap();

    let good = chain_of(2, &id);
    let mut bad = good.clone();
    bad.push(entry(99, Digest::of(b"gap"), &id, "Gap"));

    assert!(repo.append(&bad).is_err());
    assert_eq!(repo.head().unwrap(), before, "failed append changed state");
}

#[test]
fn empty_repository_has_no_head() {
    let (repo, _guard) = sql_repo!();
    assert!(repo.head().unwrap().is_none());
}

#[test]
fn a_forked_append_is_refused() {
    let (mut repo, _guard) = sql_repo!();
    let id = Identity::generate().unwrap();
    repo.append(&chain_of(3, &id)).unwrap();

    // Correct seq, wrong prev - the shape a fork actually takes.
    let forked = entry(3, Digest::of(b"different history"), &id, "Fork");
    assert!(matches!(
        repo.append(&[forked]),
        Err(remotino_crypto::Error::ChainIntegrity(_))
    ));
}

#[test]
fn head_matches_the_last_appended_entry() {
    let (mut repo, _guard) = sql_repo!();
    let id = Identity::generate().unwrap();
    let entries = chain_of(4, &id);
    let expected = Head {
        seq: 3,
        digest: entries.last().unwrap().digest().unwrap(),
    };
    repo.append(&entries).unwrap();
    assert_eq!(repo.head().unwrap().unwrap(), expected);
}
