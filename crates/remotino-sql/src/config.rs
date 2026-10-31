//! Connection configuration.
//!
//! Deliberately narrow: a host, a database, and how to authenticate. Everything that
//! could weaken transport security is either absent or requires saying so out loud.

use tiberius::{AuthMethod, Config, EncryptionLevel};

/// How to authenticate to the server.
///
/// No shared application login exists as a variant, and that is the point. A shared
/// credential sits in every client's config, any user can extract it, and they would then
/// hold whatever rights it carries - discarding the guarantee SQL Server was chosen for
/// (`DESIGN.md` 3).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Auth {
    /// Windows integrated authentication.
    ///
    /// Used by LocalDB single-seat installs, and by any future Active Directory
    /// deployment (`SQL-SETUP.md` 9). Carries no password for us to store.
    Integrated,

    /// SQL Authentication with a per-user login.
    ///
    /// The password is expected to have been unsealed from the user's identity moments
    /// before, and to be dropped immediately after connecting - it is never persisted by
    /// this crate.
    SqlLogin {
        /// Login name, e.g. `remotino_alice`.
        username: String,
        /// Password, unsealed from the user's vault.
        password: String,
    },
}

/// Where and how to connect.
#[derive(Debug, Clone)]
pub struct SqlConfig {
    /// Host name or address.
    pub host: String,
    /// TCP port. `DESIGN.md` 3 recommends a static port over SQL Browser.
    pub port: u16,
    /// Named instance, e.g. `SQLEXPRESS`. `None` for a default instance or LocalDB.
    pub instance: Option<String>,
    /// Database name.
    pub database: String,
    /// How to authenticate.
    pub auth: Auth,
    /// Accept the server's certificate without validating it.
    ///
    /// **Off by default, and it should stay off.** Express installs with a self-signed
    /// certificate, which is fine on a LAN *provided the client pins it*; blanket trust
    /// reintroduces exactly the man-in-the-middle exposure TLS was there to remove
    /// (`SQL-SETUP.md` 6). Present only so a first-run diagnostic can distinguish "TLS is
    /// misconfigured" from "the server is unreachable", and named to be uncomfortable.
    pub trust_server_certificate_danger: bool,
}

impl SqlConfig {
    /// A local development configuration against `.\SQLEXPRESS`.
    ///
    /// Integrated auth and certificate trust, because it is pointed at a loopback
    /// instance the developer already administers. Not for anything else.
    #[must_use]
    pub fn local_dev(database: &str) -> Self {
        Self {
            host: "localhost".to_owned(),
            port: 1433,
            instance: Some("SQLEXPRESS".to_owned()),
            database: database.to_owned(),
            auth: Auth::Integrated,
            trust_server_certificate_danger: true,
        }
    }

    pub(crate) fn to_tiberius(&self) -> Config {
        let mut cfg = Config::new();
        cfg.host(&self.host);
        cfg.port(self.port);
        if let Some(instance) = &self.instance {
            cfg.instance_name(instance);
        }
        cfg.database(&self.database);

        match &self.auth {
            Auth::SqlLogin { username, password } => {
                cfg.authentication(AuthMethod::sql_server(username, password));
            }
            // Windows integrated auth is SSPI, which tiberius only provides on Windows. On
            // macOS/Linux it does not exist, so we leave the default (unauthenticated) - a
            // client there must use a SQL login. The setup flow points macOS users at SQL
            // logins / setup codes, so this path is not reached in practice off Windows.
            Auth::Integrated => {
                #[cfg(windows)]
                cfg.authentication(AuthMethod::Integrated);
            }
        }

        // Encryption is always requested. The only knob is whether the certificate is
        // validated, and that one is named to discourage its use.
        cfg.encryption(EncryptionLevel::Required);
        if self.trust_server_certificate_danger {
            cfg.trust_cert();
        }
        cfg
    }
}
