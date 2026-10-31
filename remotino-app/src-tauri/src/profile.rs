//! Which chain backend the app uses: the local single-seat SQLite file, or a shared SQL
//! Server. Stored as plain JSON in the app data dir (`connection.json`).
//!
//! **The SQL-login password is sealed to the user's identity** ([`password_sealed`]): it is
//! stored as an ECIES wrap under the `sql-password` context, so the file on disk reveals
//! nothing without the unlocked identity, and it decrypts only after unlock. A brief
//! interim window can hold a cleartext [`password`] - when the backend is configured before
//! any identity exists - which is upgraded to the sealed form on the next unlock.
//!
//! [`password_sealed`]: SqlProfile::password_sealed
//! [`password`]: SqlProfile::password

use std::path::Path;

use remotino_crypto::envelope::{open_sealed, seal_to, WrappedKey, CONTEXT_SQL_PASSWORD};
use remotino_crypto::identity::Identity;
use remotino_pg::{PgConfig, PgTls};
use remotino_sql::{Auth, SqlConfig};
use serde::{Deserialize, Serialize};

/// How to authenticate to SQL Server.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SqlAuthMode {
    /// Windows integrated auth (no stored password).
    #[default]
    Integrated,
    /// A SQL Server login (username + password).
    Sql,
}

/// A shared SQL Server connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SqlProfile {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub instance: Option<String>,
    pub database: String,
    #[serde(default)]
    pub trust_cert: bool,
    #[serde(default)]
    pub auth: SqlAuthMode,
    #[serde(default)]
    pub username: Option<String>,
    /// Cleartext password, present only for the transient "test connection" path from the
    /// UI, and as an interim store when no identity exists yet to seal it to. Once an
    /// identity is available it is moved into [`password_sealed`] and cleared.
    #[serde(default)]
    pub password: Option<String>,
    /// The login password sealed to the user's identity (hex of a CBOR-encoded
    /// [`WrappedKey`] under [`CONTEXT_SQL_PASSWORD`]). Unreadable without the unlocked
    /// identity. This is the at-rest form.
    #[serde(default)]
    pub password_sealed: Option<String>,
}

impl SqlProfile {
    /// A [`SqlConfig`] from the fields as-is, using the cleartext [`password`] if present.
    /// Used by the UI "test connection" path, where the password was just typed in.
    ///
    /// [`password`]: SqlProfile::password
    pub fn to_config(&self) -> SqlConfig {
        self.to_config_with_password(self.password.clone().unwrap_or_default())
    }

    /// A [`SqlConfig`] with the password resolved for `identity`: the sealed password
    /// unwrapped if present, else the cleartext interim password. Used at unlock, when the
    /// identity is available.
    pub fn to_config_for(&self, identity: &Identity) -> Result<SqlConfig, String> {
        let password = self.resolve_password(identity)?.unwrap_or_default();
        Ok(self.to_config_with_password(password))
    }

    fn to_config_with_password(&self, password: String) -> SqlConfig {
        let auth = match self.auth {
            SqlAuthMode::Sql => Auth::SqlLogin {
                username: self.username.clone().unwrap_or_default(),
                password,
            },
            SqlAuthMode::Integrated => Auth::Integrated,
        };
        SqlConfig {
            host: self.host.clone(),
            port: self.port,
            instance: self.instance.clone(),
            database: self.database.clone(),
            auth,
            trust_server_certificate_danger: self.trust_cert,
        }
    }

    /// The cleartext login password for `identity`: unseals [`password_sealed`] if set,
    /// otherwise returns the interim cleartext [`password`].
    ///
    /// [`password_sealed`]: SqlProfile::password_sealed
    /// [`password`]: SqlProfile::password
    pub fn resolve_password(&self, identity: &Identity) -> Result<Option<String>, String> {
        if let Some(sealed) = &self.password_sealed {
            return Ok(Some(open_password(identity, sealed)?));
        }
        Ok(self.password.clone())
    }

    /// Returns a copy of this profile with any cleartext password sealed to `identity` and
    /// removed from the clear. A no-op if there is nothing to seal (integrated auth, or the
    /// password is already sealed and no fresh cleartext was supplied).
    pub fn sealed_to(&self, identity: &Identity) -> Result<Self, String> {
        let mut out = self.clone();
        if !matches!(out.auth, SqlAuthMode::Sql) {
            // Not a SQL login: no password to keep.
            out.password = None;
            out.password_sealed = None;
            return Ok(out);
        }
        if let Some(cleartext) = out.password.take().filter(|p| !p.is_empty()) {
            out.password_sealed = Some(seal_password(identity, &cleartext)?);
        }
        // Drop any lingering cleartext even if empty.
        out.password = None;
        Ok(out)
    }
}

/// A shared Postgres connection. Postgres always authenticates with a login, so the password
/// is sealed to the identity exactly like [`SqlProfile`]'s (same `CONTEXT_SQL_PASSWORD`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PgProfile {
    pub host: String,
    pub port: u16,
    pub database: String,
    #[serde(default)]
    pub username: Option<String>,
    /// Cleartext password (transient / interim only), sealed and cleared once an identity
    /// exists. See [`SqlProfile::password`].
    #[serde(default)]
    pub password: Option<String>,
    /// Password sealed to the identity (hex CBOR [`WrappedKey`]). The at-rest form.
    #[serde(default)]
    pub password_sealed: Option<String>,
    /// Require TLS. When false the connection is plaintext (loopback / throwaway only).
    #[serde(default)]
    pub require_tls: bool,
    /// The trusted server-certificate fingerprint (SHA-256, hex; colons optional), pinned on
    /// first use. `None` until the user has approved one. Only meaningful with `require_tls`.
    #[serde(default)]
    pub pinned_fingerprint: Option<String>,
}

impl PgProfile {
    /// A [`PgConfig`] using the cleartext password if present (the UI "test" path).
    pub fn to_config(&self) -> PgConfig {
        self.to_config_with_password(self.password.clone().unwrap_or_default())
    }

    /// A [`PgConfig`] with the password resolved for `identity` (unsealed if sealed).
    pub fn to_config_for(&self, identity: &Identity) -> Result<PgConfig, String> {
        let password = self.resolve_password(identity)?.unwrap_or_default();
        Ok(self.to_config_with_password(password))
    }

    fn to_config_with_password(&self, password: String) -> PgConfig {
        let tls = if self.require_tls {
            PgTls::Require {
                pinned_sha256: self
                    .pinned_fingerprint
                    .as_deref()
                    .and_then(parse_fingerprint),
            }
        } else {
            PgTls::Disable
        };
        PgConfig {
            host: self.host.clone(),
            port: self.port,
            database: self.database.clone(),
            user: self.username.clone().unwrap_or_default(),
            password,
            tls,
        }
    }

    /// The cleartext password for `identity`: unseals `password_sealed` if set, else the
    /// interim cleartext `password`.
    pub fn resolve_password(&self, identity: &Identity) -> Result<Option<String>, String> {
        if let Some(sealed) = &self.password_sealed {
            return Ok(Some(open_password(identity, sealed)?));
        }
        Ok(self.password.clone())
    }

    /// A copy with any cleartext password sealed to `identity` and removed from the clear.
    pub fn sealed_to(&self, identity: &Identity) -> Result<Self, String> {
        let mut out = self.clone();
        if let Some(cleartext) = out.password.take().filter(|p| !p.is_empty()) {
            out.password_sealed = Some(seal_password(identity, &cleartext)?);
        }
        out.password = None;
        Ok(out)
    }
}

/// Parses a SHA-256 certificate fingerprint (64 hex chars, colons/whitespace ignored) into
/// raw bytes. Returns `None` for anything that isn't exactly 32 bytes of hex.
fn parse_fingerprint(s: &str) -> Option<[u8; 32]> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace() && *c != ':').collect();
    let bytes = hex::decode(cleaned).ok()?;
    bytes.try_into().ok()
}

/// Seals a SQL login password to an identity: hex of a CBOR-encoded [`WrappedKey`].
fn seal_password(identity: &Identity, password: &str) -> Result<String, String> {
    let wrapped = seal_to(identity.public(), password.as_bytes(), CONTEXT_SQL_PASSWORD)
        .map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    ciborium::into_writer(&wrapped, &mut buf).map_err(|e| e.to_string())?;
    Ok(hex::encode(buf))
}

/// Unseals a SQL login password sealed by [`seal_password`].
fn open_password(identity: &Identity, sealed_hex: &str) -> Result<String, String> {
    let bytes = hex::decode(sealed_hex).map_err(|_| "sealed password unreadable".to_owned())?;
    let wrapped: WrappedKey =
        ciborium::from_reader(bytes.as_slice()).map_err(|_| "sealed password unreadable".to_owned())?;
    let plaintext =
        open_sealed(&wrapped, identity, CONTEXT_SQL_PASSWORD).map_err(|_| "cannot unseal SQL password".to_owned())?;
    String::from_utf8(plaintext.to_vec()).map_err(|_| "SQL password not valid UTF-8".to_owned())
}

/// The active backend.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(tag = "backend", rename_all = "lowercase")]
pub enum ConnectionProfile {
    /// Local single-seat SQLite store.
    #[default]
    Local,
    /// Shared SQL Server.
    Sql(SqlProfile),
    /// Shared Postgres.
    Pg(PgProfile),
}

pub fn load(path: &Path) -> ConnectionProfile {
    std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

pub fn save(path: &Path, profile: &ConnectionProfile) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(profile).map_err(|e| e.to_string())?;
    std::fs::write(path, bytes).map_err(|e| e.to_string())
}
