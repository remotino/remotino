//! Live integration tests for the Postgres backend.
//!
//! Marked `#[ignore]` so `cargo test` stays green without a database. Run explicitly against
//! a throwaway Postgres:
//!
//! ```text
//! docker run --name remotino-pg -e POSTGRES_PASSWORD=devpass -p 5432:5432 -d postgres:16
//! cargo test -p remotino-pg -- --ignored
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use remotino_crypto::chain::{Entry, EntryBody};
use remotino_crypto::envelope::{open_sealed, WrappedKey, CONTEXT_SQL_PASSWORD};
use remotino_crypto::identity::Identity;
use remotino_crypto::repository::Repository;
use remotino_crypto::Digest;
use remotino_pg::{
    drop_database, ensure_database, probe_certificate, provision_login, PgConfig, PgRepo, PgTls,
};

/// Admin config against the local docker container (superuser `postgres`).
fn admin_config(database: &str) -> PgConfig {
    PgConfig::local_dev(database, "postgres", "devpass")
}

fn signed(seq: u64, prev: Digest, id: &Identity, action: &str) -> Entry {
    let body = EntryBody {
        seq,
        prev,
        timestamp: "2026-01-01T00:00:00Z".to_owned(),
        actor: id.key_id(),
        action: action.to_owned(),
        payload: format!("payload-{seq}").into_bytes(),
    };
    Entry::sign(body, id).expect("sign entry")
}

#[test]
#[ignore = "needs a live Postgres (see module docs)"]
fn append_read_head_and_append_only_enforcement() {
    let db = "remotino_pgtest";
    let cfg = admin_config(db);

    // Fresh database every run.
    drop_database(&cfg).expect("drop (pre)");
    ensure_database(&cfg).expect("ensure database");
    let mut repo = PgRepo::connect_and_migrate(&cfg).expect("connect + migrate");

    // Empty to start.
    assert!(repo.head().unwrap().is_none(), "fresh repo has no head");
    assert!(repo.read_from(None).unwrap().is_empty());

    // Build a 3-entry chain: genesis + two links. Capture digests before moving the entries.
    let id = Identity::generate().unwrap();
    let e0 = signed(0, Digest::ZERO, &id, "FolderCreated");
    let d0 = e0.digest().unwrap();
    let e1 = signed(1, d0, &id, "EntryUpserted");
    let d1 = e1.digest().unwrap();
    let e2 = signed(2, d1, &id, "AclGranted");
    let d2 = e2.digest().unwrap();

    // Append as one atomic batch.
    let head = repo.append(&[e0, e1, e2]).expect("append");
    assert_eq!(head.seq, 2);

    // Read back in order.
    let all = repo.read_from(None).unwrap();
    assert_eq!(all.len(), 3);
    assert_eq!(all[0].body.seq, 0);
    assert_eq!(all[1].body.seq, 1);
    assert_eq!(all[2].body.seq, 2);
    // Incremental read from a cursor.
    assert_eq!(repo.read_from(Some(0)).unwrap().len(), 2);

    // Head matches the last entry.
    let h = repo.head().unwrap().expect("head present");
    assert_eq!(h.seq, 2);
    assert_eq!(h.digest, d2);
    assert_eq!(all[0].digest().unwrap(), d0);
    assert_eq!(all[1].digest().unwrap(), d1);

    // Append-only enforcement: the trigger must reject UPDATE and DELETE on events, even for
    // the superuser we're connected as.
    assert!(
        repo.execute_raw_for_tests("DELETE FROM events WHERE seq = 0").is_err(),
        "DELETE on events must be blocked by the append-only trigger"
    );
    assert!(
        repo.execute_raw_for_tests("UPDATE events SET signature = signature WHERE seq = 0").is_err(),
        "UPDATE on events must be blocked by the append-only trigger"
    );

    // The chain is still intact after the blocked attempts.
    assert_eq!(repo.read_from(None).unwrap().len(), 3);

    // Connected as superuser, over_privileged() should be true (this is the "wrong login" the
    // app warns about; a provisioned remotino_user login returns false).
    assert!(repo.over_privileged().unwrap());

    // Clean up.
    drop(repo);
    drop_database(&cfg).expect("drop (post)");
}

#[test]
#[ignore = "needs a live Postgres (see module docs)"]
fn provisioned_login_is_least_privilege() {
    let db = "remotino_pgtest_prov";
    let admin = admin_config(db);
    let login = "remotino_alice";

    drop_database(&admin).expect("drop (pre)");
    ensure_database(&admin).expect("ensure database");
    let mut admin_repo = PgRepo::connect_and_migrate(&admin).expect("connect + migrate");

    // Seed one entry as admin so there's something to read/extend.
    let id = Identity::generate().unwrap();
    let e0 = signed(0, Digest::ZERO, &id, "FolderCreated");
    let d0 = e0.digest().unwrap();
    admin_repo.append(&[e0]).expect("seed append");

    // Provision Alice's login; unseal the password with her identity (as the app would).
    let provisioned = provision_login(&admin_repo, login, db, id.public()).expect("provision");
    assert_eq!(provisioned.login, login);
    let wrapped: WrappedKey =
        ciborium::from_reader(provisioned.sealed_password.as_slice()).expect("decode wrapped");
    let password = open_sealed(&wrapped, &id, CONTEXT_SQL_PASSWORD).expect("unseal password");
    let password = String::from_utf8(password.to_vec()).expect("utf8");

    // Connect AS the provisioned least-privilege login.
    let alice_cfg = PgConfig::local_dev(db, login, &password);
    let mut alice = PgRepo::connect_checked(&alice_cfg).expect("alice connects");

    // She can read...
    assert_eq!(alice.read_from(None).unwrap().len(), 1);
    // ...and append (INSERT is granted)...
    let e1 = signed(1, d0, &id, "EntryUpserted");
    alice.append(&[e1]).expect("alice can append");
    assert_eq!(alice.read_from(None).unwrap().len(), 2);
    // ...but NOT modify or delete history (no grant, and the trigger).
    assert!(alice.execute_raw_for_tests("DELETE FROM events").is_err());
    assert!(alice.execute_raw_for_tests("UPDATE events SET seq = seq").is_err());
    // ...and she is correctly seen as least-privilege (the app's warning stays quiet for her).
    assert!(!alice.over_privileged().unwrap(), "provisioned login must not be over-privileged");

    // Cleanup.
    drop(alice);
    admin_repo.deprovision_login(login).expect("deprovision");
    drop(admin_repo);
    drop_database(&admin).expect("drop (post)");
}

/// TLS with trust-on-first-use pinning, against a **separate** SSL-enabled container on 5433:
///
/// ```text
/// docker run -d --name remotino-pg-tls -e POSTGRES_PASSWORD=devpass -p 5433:5432 postgres:16
/// docker exec remotino-pg-tls bash -c "cd /var/lib/postgresql/data && \
///   openssl req -new -x509 -days 365 -nodes -text -out server.crt -keyout server.key \
///   -subj '/CN=remotino-db.local' && chmod 600 server.key && \
///   chown postgres:postgres server.key server.crt"
/// docker exec -u postgres remotino-pg-tls psql -c "ALTER SYSTEM SET ssl='on';"
/// docker restart remotino-pg-tls
/// ```
#[test]
#[ignore = "needs the SSL-enabled Postgres on :5433 (see this fn's docs)"]
fn tls_tofu_pinning() {
    let db = "remotino_pgtls";
    // Config pointed at the TLS container (:5433), with a given TLS mode.
    let cfg = |database: &str, tls: PgTls| PgConfig {
        host: "localhost".to_owned(),
        port: 5433,
        database: database.to_owned(),
        user: "postgres".to_owned(),
        password: "devpass".to_owned(),
        tls,
    };

    // 1. Probe the certificate to obtain its fingerprint (what the approval popup shows). No
    //    pin needed for a probe - it captures the cert and closes the handshake.
    let probe = cfg("postgres", PgTls::Require { pinned_sha256: None });
    let info = probe_certificate(&probe).expect("probe returns the server certificate");
    assert_eq!(info.sha256.len(), 32);
    assert!(info.fingerprint.contains(':'), "fingerprint is colon-grouped hex");
    assert!(
        info.subject.contains("remotino-db.local"),
        "subject should carry the CN we issued: {}",
        info.subject
    );

    // 2. Pin that exact fingerprint: the full setup flow (create db + migrate) works over TLS.
    let trusted = cfg(db, PgTls::Require { pinned_sha256: Some(info.sha256) });
    drop_database(&trusted).expect("drop (pre)");
    ensure_database(&trusted).expect("create database over TLS");
    let repo = PgRepo::connect_and_migrate(&trusted).expect("connect + migrate over pinned TLS");
    assert!(repo.head().unwrap().is_none(), "fresh repo, no head");
    drop(repo);

    // 3. TLS required but nothing pinned: a connect to the now-working db is still refused -
    //    proving the refusal is the pin check, not a missing schema.
    let untrusted = cfg(db, PgTls::Require { pinned_sha256: None });
    assert!(
        PgRepo::connect_checked(&untrusted).is_err(),
        "TLS required with nothing pinned must fail"
    );

    // 4. Pin a WRONG fingerprint: a MITM / cert swap is rejected.
    let mut wrong = info.sha256;
    wrong[0] ^= 0xff;
    let bad = cfg(db, PgTls::Require { pinned_sha256: Some(wrong) });
    assert!(
        PgRepo::connect_checked(&bad).is_err(),
        "a certificate that doesn't match the pin must be rejected"
    );

    drop_database(&trusted).expect("drop (post)");
}
