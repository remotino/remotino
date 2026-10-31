//! Per-user Postgres login provisioning.
//!
//! Mirrors `remotino-sql`'s provisioning: an admin creates a login with a random password,
//! adds it to the least-privilege `remotino_user` role, and gets back the password **sealed
//! to the user's identity** (same `CONTEXT_SQL_PASSWORD` envelope the app already unseals for
//! SQL Server). The user never sees or types the password; their passphrase unwraps it at
//! sign-in.
//!
//! Requires admin rights (`CREATE ROLE`), so this runs under the transient admin credential
//! the setup flow holds - never from an ordinary session.

use remotino_crypto::envelope::{self, CONTEXT_SQL_PASSWORD};
use remotino_crypto::identity::PublicIdentity;
use zeroize::Zeroizing;

use crate::config::validate_identifier;
use crate::repo::PgRepo;
use crate::{Error, Result};

/// The result of provisioning: a login name and the password sealed to its owner.
///
/// The plaintext is deliberately absent - it existed only long enough to create the role and
/// seal it. The admin hands `sealed_password` to the user (e.g. as a setup code); the user's
/// identity unwraps it at sign-in.
#[derive(Debug, Clone)]
pub struct ProvisionedLogin {
    /// The Postgres role/login name, e.g. `remotino_alice`.
    pub login: String,
    /// The login password, sealed to the user's wrapping key: serialised
    /// [`remotino_crypto::envelope::WrappedKey`] bytes under [`CONTEXT_SQL_PASSWORD`].
    pub sealed_password: Vec<u8>,
}

/// A random 24-byte (48 hex char) password. Postgres has no complexity policy, so a plain
/// hex string is fine and avoids any quoting concerns.
fn generate_password() -> Result<Zeroizing<String>> {
    let mut raw = Zeroizing::new([0u8; 24]);
    getrandom::fill(raw.as_mut()).map_err(|_| Error::MalformedRow {
        seq: -1,
        reason: "OS random source unavailable",
    })?;
    Ok(Zeroizing::new(hex::encode(raw.as_ref())))
}

/// Provisions a login for a user and seals its password to their identity.
///
/// `repo` must be connected as an administrator to the target `database`. `login` is the role
/// name (convention `remotino_<user>`). `recipient` is the user's published public identity.
///
/// Idempotent on the login: an existing role has its password rotated rather than failing -
/// the intended way to rotate a credential.
///
/// # Errors
///
/// SQL failures, a bad identifier, or a sealing failure.
pub fn provision_login(
    repo: &PgRepo,
    login: &str,
    database: &str,
    recipient: &PublicIdentity,
) -> Result<ProvisionedLogin> {
    validate_identifier(login)?;
    validate_identifier(database)?;
    let password = generate_password()?;

    // Seal before touching the database: if sealing fails we have created nothing.
    let wrapped = envelope::seal_to(recipient, password.as_bytes(), CONTEXT_SQL_PASSWORD)
        .map_err(Error::Crypto)?;
    let mut sealed_password = Vec::new();
    ciborium::into_writer(&wrapped, &mut sealed_password).map_err(|_| Error::MalformedRow {
        seq: -1,
        reason: "could not encode sealed password",
    })?;

    repo.run_provisioning(login, &password, database)?;

    Ok(ProvisionedLogin {
        login: login.to_owned(),
        sealed_password,
    })
}
