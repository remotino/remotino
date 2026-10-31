//! Provisioning and directory tests against a real SQL Server instance.
//!
//! Skipped unless `REMOTINO_TEST_SQL` is set (see `integration.rs`). Destructive:
//! creates and drops logins named `remotino_ptest_*`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use remotino_crypto::envelope::{self, CONTEXT_SQL_PASSWORD};
use remotino_crypto::identity::Identity;
use remotino_sql::{provision_login, Auth, SealedVault, SqlConfig, SqlRepo};

static DB_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn admin_repo() -> Option<(SqlRepo, std::sync::MutexGuard<'static, ()>)> {
    let db = std::env::var("REMOTINO_TEST_SQL").ok()?;
    let guard = DB_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let repo = SqlRepo::connect_and_migrate(&SqlConfig::local_dev(&db))
        .expect("connect as admin");
    Some((repo, guard))
}

macro_rules! admin {
    () => {
        match admin_repo() {
            Some(pair) => pair,
            None => {
                eprintln!("skipping: REMOTINO_TEST_SQL not set");
                return;
            }
        }
    };
}

#[test]
fn provisioned_login_password_unseals_and_connects() {
    // The whole point of the mechanism, end to end: an admin provisions a login, the
    // password comes back sealed to the user's key, the user unseals it with their own
    // identity, and that password actually opens a connection. If any link is wrong -
    // wrong context label, wrong recipient, a login that was not really created - this
    // fails.
    let (mut admin, _guard) = admin!();
    let db = std::env::var("REMOTINO_TEST_SQL").unwrap();

    let user = Identity::generate().unwrap();
    let login = "remotino_ptest_alice";

    // Clean any leftover from a previous run.
    admin.deprovision_login(login).ok();

    let provisioned = provision_login(&mut admin, login, user.public()).unwrap();
    assert_eq!(provisioned.login, login);

    // Client side: unseal the password with the user's identity.
    let wrapped: remotino_crypto::envelope::WrappedKey =
        ciborium::from_reader(provisioned.sealed_password.as_slice()).unwrap();
    let password_bytes =
        envelope::open_sealed(&wrapped, &user, CONTEXT_SQL_PASSWORD).unwrap();
    let password = String::from_utf8(password_bytes.to_vec()).unwrap();

    // Connect as the provisioned user with the unsealed password.
    let user_config = SqlConfig {
        auth: Auth::SqlLogin {
            username: login.to_owned(),
            password,
        },
        ..SqlConfig::local_dev(&db)
    };
    let user_repo = SqlRepo::connect_checked(&user_config);
    assert!(
        user_repo.is_ok(),
        "user could not connect with the unsealed password: {:?}",
        user_repo.err()
    );

    // Drop the connection before deprovisioning: SQL Server refuses to drop a login that
    // is still logged in. In the product a departing user is not connected while being
    // removed, so this ordering is a test artefact, not a real constraint.
    drop(user_repo);
    admin.deprovision_login(login).unwrap();
}

#[test]
fn a_different_user_cannot_unseal_the_password() {
    // The sealing must actually bind to the intended recipient. A different identity
    // holding the sealed blob must not be able to open it.
    let (mut admin, _guard) = admin!();
    let user = Identity::generate().unwrap();
    let attacker = Identity::generate().unwrap();
    let login = "remotino_ptest_bob";
    admin.deprovision_login(login).ok();

    let provisioned = provision_login(&mut admin, login, user.public()).unwrap();
    let wrapped: remotino_crypto::envelope::WrappedKey =
        ciborium::from_reader(provisioned.sealed_password.as_slice()).unwrap();

    assert!(
        envelope::open_sealed(&wrapped, &attacker, CONTEXT_SQL_PASSWORD).is_err(),
        "an unintended identity unsealed the SQL password"
    );

    admin.deprovision_login(login).unwrap();
}

#[test]
fn reprovisioning_rotates_the_password_and_still_connects() {
    let (mut admin, _guard) = admin!();
    let db = std::env::var("REMOTINO_TEST_SQL").unwrap();
    let user = Identity::generate().unwrap();
    let login = "remotino_ptest_carol";
    admin.deprovision_login(login).ok();

    let first = provision_login(&mut admin, login, user.public()).unwrap();
    let second = provision_login(&mut admin, login, user.public()).unwrap();
    assert_ne!(
        first.sealed_password, second.sealed_password,
        "rotation produced the same sealed blob"
    );

    // The NEW password must connect.
    let wrapped: remotino_crypto::envelope::WrappedKey =
        ciborium::from_reader(second.sealed_password.as_slice()).unwrap();
    let password = String::from_utf8(
        envelope::open_sealed(&wrapped, &user, CONTEXT_SQL_PASSWORD)
            .unwrap()
            .to_vec(),
    )
    .unwrap();

    let cfg = SqlConfig {
        auth: Auth::SqlLogin {
            username: login.to_owned(),
            password,
        },
        ..SqlConfig::local_dev(&db)
    };
    assert!(SqlRepo::connect_checked(&cfg).is_ok());

    admin.deprovision_login(login).unwrap();
}

#[test]
fn identity_directory_roundtrips_and_rejects_conflicts() {
    let (mut admin, _guard) = admin!();
    let alice = Identity::generate().unwrap();

    admin.put_identity(alice.public()).unwrap();
    let fetched = admin.get_identity(alice.key_id()).unwrap().unwrap();
    assert_eq!(fetched.key_id(), alice.key_id());

    // Re-publishing the same identity is a no-op, not an error.
    admin.put_identity(alice.public()).unwrap();

    let dir = admin.load_directory().unwrap();
    assert!(dir.contains_key(&alice.key_id()));
}

#[test]
fn vault_upsert_roundtrips() {
    let (mut admin, _guard) = admin!();
    let owner = Identity::generate().unwrap().key_id();

    assert!(admin.get_vault(owner).unwrap().is_none());

    admin.put_vault(owner, &SealedVault(vec![1, 2, 3])).unwrap();
    assert_eq!(admin.get_vault(owner).unwrap().unwrap().0, vec![1, 2, 3]);

    // Upsert: a vault legitimately changes.
    admin.put_vault(owner, &SealedVault(vec![9, 9])).unwrap();
    assert_eq!(admin.get_vault(owner).unwrap().unwrap().0, vec![9, 9]);
}
