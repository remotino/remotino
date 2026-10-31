//! Per-user SQL login provisioning (`DESIGN.md` 3).
//!
//! This is what makes "one passphrase unlocks everything" real. When an admin enrols a
//! user:
//!
//! 1. A random SQL Server password is generated.
//! 2. A login and database user are created and added to `remotino_user`.
//! 3. The password is **sealed to the user's X25519 public key** and returned, for the
//!    admin to store in the repository alongside the user's enrolment.
//!
//! The user never sees or types the SQL password. At sign-in their passphrase unlocks
//! their identity, which unwraps this password, which opens the connection.
//!
//! # Why sealed, not delivered
//!
//! A per-user credential has to reach the user somehow. Sealing it to their public key
//! means it can travel through the same untrusted store as everything else: only the
//! holder of the matching private key can unwrap it, and that key never left their
//! machine. No out-of-band channel, no shared secret.
//!
//! # Requires admin rights
//!
//! `CREATE LOGIN` / `CREATE USER` / `ALTER ROLE` are not granted to `remotino_user`, so
//! this runs under the transient admin credential the provisioning wizard holds - never
//! from an ordinary session.

use remotino_crypto::envelope::{self, CONTEXT_SQL_PASSWORD};
use remotino_crypto::identity::PublicIdentity;
use zeroize::Zeroizing;

use crate::repo::SqlRepo;
use crate::{Error, Result};

/// The result of provisioning: a login name and the password sealed to its owner.
///
/// The plaintext password is deliberately absent - it existed only long enough to create
/// the login and seal it, and was zeroized in between. The admin stores `sealed_password`
/// in the repo; the user unwraps it at sign-in.
#[derive(Debug, Clone)]
pub struct ProvisionedLogin {
    /// SQL Server login name, e.g. `remotino_alice`.
    pub login: String,
    /// The login password, sealed to the user's wrapping key.
    ///
    /// Serialised [`remotino_crypto::envelope::WrappedKey`] bytes. Opaque here; the
    /// client unwraps it with its identity and [`CONTEXT_SQL_PASSWORD`].
    pub sealed_password: Vec<u8>,
}

/// Generates a random SQL Server password meeting the default complexity policy.
///
/// `CHECK_POLICY = ON` requires three of four character classes, so a raw random string
/// can be rejected. This draws from all four explicitly, then fills the rest from a wide
/// alphabet, so it always passes without a retry loop.
fn generate_password() -> Result<Zeroizing<String>> {
    const UPPER: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
    const LOWER: &[u8] = b"abcdefghijkmnpqrstuvwxyz";
    const DIGIT: &[u8] = b"23456789";
    const SYMBOL: &[u8] = b"!#%*+-=?@_";
    const ALL: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!#%*+-=?@_";

    // 36 bytes of randomness mapped to the alphabet. Rejection-free: we pick from each
    // required class first so complexity is guaranteed regardless of the draw.
    let mut raw = Zeroizing::new([0u8; 36]);
    getrandom::fill(raw.as_mut()).map_err(|_| Error::MalformedRow {
        seq: -1,
        reason: "OS random source unavailable",
    })?;

    let mut chars: Vec<u8> = Vec::with_capacity(raw.len());
    // Guaranteed one of each required class, then fill from the full alphabet. Zip each
    // random byte with the class it should draw from - no indexing, so nothing to
    // panic. The four required classes come first, the rest all draw from `ALL`.
    let classes = [UPPER, LOWER, DIGIT, SYMBOL];
    for (i, &b) in raw.iter().enumerate() {
        let alphabet = classes.get(i).copied().unwrap_or(ALL);
        push_from(&mut chars, alphabet, b);
    }

    let password = String::from_utf8(chars).map_err(|_| Error::MalformedRow {
        seq: -1,
        reason: "generated password was not utf-8",
    })?;
    Ok(Zeroizing::new(password))
}

fn push_from(out: &mut Vec<u8>, alphabet: &[u8], byte: u8) {
    // `checked_rem` rather than `%`: the workspace lints forbid bare arithmetic in
    // library code, and while these alphabets are compile-time non-empty, "obviously
    // fine" is precisely the reasoning those lints exist to stop. An empty alphabet
    // would yield `None` and simply contribute no character.
    if let Some(idx) = (byte as usize).checked_rem(alphabet.len())
        && let Some(&c) = alphabet.get(idx)
    {
        out.push(c);
    }
}

/// Provisions a SQL login for a user and seals its password to their identity.
///
/// `repo` must be connected as an administrator. `login` is the SQL login name; convention
/// is `remotino_<user>`. `recipient` is the user's public identity, published beforehand.
///
/// Idempotent on the login name: if the login already exists it is left in place and a
/// fresh password is set, so re-running rotates the credential rather than failing. That
/// is the intended way to rotate - a leaked SQL password is low-stakes (`DESIGN.md` 3),
/// but rotating it should still be one call.
///
/// # Errors
///
/// SQL failures, or a sealing failure.
pub fn provision_login(
    repo: &mut SqlRepo,
    login: &str,
    recipient: &PublicIdentity,
) -> Result<ProvisionedLogin> {
    validate_login_name(login)?;
    let password = generate_password()?;

    // Seal BEFORE touching the database: if sealing fails we have created nothing, and if
    // the DB work fails we have leaked nothing (the plaintext is about to be dropped).
    let wrapped = envelope::seal_to(recipient, password.as_bytes(), CONTEXT_SQL_PASSWORD)
        .map_err(Error::Crypto)?;
    let mut sealed_password = Vec::new();
    ciborium::into_writer(&wrapped, &mut sealed_password).map_err(|_| Error::MalformedRow {
        seq: -1,
        reason: "could not encode sealed password",
    })?;

    repo.run_provisioning(login, &password)?;

    Ok(ProvisionedLogin {
        login: login.to_owned(),
        sealed_password,
    })
}

/// Rejects login names that are not a strict identifier.
///
/// The login name is interpolated into DDL, which cannot be parameterised for object
/// names. Restricting it to `[A-Za-z0-9_]` (and a length cap) makes injection structurally
/// impossible rather than relying on escaping - the login name comes from an admin, but
/// "comes from an admin" is not a reason to hand it to string concatenation unchecked.
fn validate_login_name(login: &str) -> Result<()> {
    let ok = !login.is_empty()
        && login.len() <= 128
        && login
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_');
    if ok {
        Ok(())
    } else {
        Err(Error::MalformedRow {
            seq: -1,
            reason: "login name must be non-empty ASCII alphanumeric or underscore",
        })
    }
}

impl SqlRepo {
    /// Runs the DDL to create-or-update a login. Admin rights required.
    ///
    /// Split from [`provision_login`] so the crypto and the SQL live in one place each.
    /// `password` is quoted defensively even though [`generate_password`] never emits a
    /// quote; the login name is validated by [`validate_login_name`] before it reaches
    /// here.
    pub(crate) fn run_provisioning(&mut self, login: &str, password: &str) -> Result<()> {
        // Single-quotes doubled per T-SQL string-literal rules. Belt and braces: the
        // generator excludes quotes, but this function should be safe for any password.
        let escaped = password.replace('\'', "''");

        let sql = format!(
            "IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'{login}')
                 CREATE LOGIN [{login}] WITH PASSWORD = N'{escaped}', CHECK_POLICY = ON;
             ELSE
                 ALTER LOGIN [{login}] WITH PASSWORD = N'{escaped}';

             IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'{login}')
                 CREATE USER [{login}] FOR LOGIN [{login}];

             IF NOT EXISTS (
                 SELECT 1 FROM sys.database_role_members rm
                 JOIN sys.database_principals r ON rm.role_principal_id = r.principal_id
                 JOIN sys.database_principals m ON rm.member_principal_id = m.principal_id
                 WHERE r.name = 'remotino_user' AND m.name = N'{login}')
                 ALTER ROLE remotino_user ADD MEMBER [{login}];"
        );

        self.with_client(|client| Box::pin(async move {
            client.simple_query(sql).await?.into_results().await?;
            Ok(())
        }))
    }

    /// Drops a provisioned login and its database user. Admin rights required.
    ///
    /// For deprovisioning a departed user. The user's audit history stays - it is signed
    /// and immutable - but their ability to connect ends immediately.
    ///
    /// # Errors
    ///
    /// SQL failures.
    pub fn deprovision_login(&mut self, login: &str) -> Result<()> {
        validate_login_name(login)?;
        let sql = format!(
            "IF EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'{login}')
                 DROP USER [{login}];
             IF EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'{login}')
                 DROP LOGIN [{login}];"
        );
        self.with_client(|client| Box::pin(async move {
            client.simple_query(sql).await?.into_results().await?;
            Ok(())
        }))
    }
}
