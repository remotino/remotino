//! [`Repository`] over Postgres.

use std::sync::Mutex;

use remotino_crypto::chain::{Entry, Head, Seq};
use remotino_crypto::repository::Repository;
use remotino_crypto::Digest;

use crate::config::{validate_identifier, PgTls};
use crate::{schema, Error, PgConfig, Result};

pub(crate) type Client = tokio_postgres::Client;

/// An append-only chain store backed by Postgres.
///
/// Owns a current-thread Tokio runtime and blocks on it, so the synchronous [`Repository`]
/// trait stays free of an executor dependency. **Do not call from inside an async context.**
pub struct PgRepo {
    runtime: tokio::runtime::Runtime,
    /// `read_from`/`head` take `&self` by contract; `tokio_postgres` needs `&mut` for a
    /// transaction. A mutex reconciles that. One connection, used from one thread at a time.
    cell: Mutex<Client>,
}

impl core::fmt::Debug for PgRepo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PgRepo { .. }")
    }
}

fn new_runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(Error::Runtime)
}

/// Connects to `database` on the server in `config`, driving the connection on the current
/// runtime. Must be called from within a `block_on`.
async fn connect_client(config: &PgConfig, database: &str) -> Result<Client> {
    let pg = config.to_pg(database);
    // The connection future performs the actual socket I/O; it must be driven for the client
    // to make progress. On the current-thread runtime it advances during each `block_on`. The
    // TLS and plaintext connections have different future types, so each branch spawns its own.
    match &config.tls {
        PgTls::Disable => {
            let (client, connection) = pg.connect(tokio_postgres::NoTls).await?;
            tokio::spawn(async move {
                let _ = connection.await;
            });
            Ok(client)
        }
        PgTls::Require { pinned_sha256 } => {
            let connector = crate::tls::pinned_connector(*pinned_sha256)?;
            let (client, connection) = pg.connect(connector).await?;
            tokio::spawn(async move {
                let _ = connection.await;
            });
            Ok(client)
        }
    }
}

impl PgRepo {
    /// Connects and applies any outstanding migrations. Requires rights an ordinary
    /// `remotino_user` login does not have; use [`PgRepo::connect_checked`] for those.
    ///
    /// # Errors
    ///
    /// Connection and migration failures.
    pub fn connect_and_migrate(config: &PgConfig) -> Result<Self> {
        let runtime = new_runtime()?;
        let client = runtime.block_on(connect_client(config, &config.database))?;
        runtime.block_on(schema::migrate(&client))?;
        Ok(Self {
            runtime,
            cell: Mutex::new(client),
        })
    }

    /// Connects without migrating, verifying the schema is one this build understands.
    ///
    /// # Errors
    ///
    /// Connection failures, or [`Error::SchemaTooNew`].
    pub fn connect_checked(config: &PgConfig) -> Result<Self> {
        let runtime = new_runtime()?;
        let client = runtime.block_on(connect_client(config, &config.database))?;
        if let Some(found) = runtime.block_on(schema::current_version(&client))?
            && found > schema::SUPPORTED_VERSION
        {
            return Err(Error::SchemaTooNew {
                found,
                supported: schema::SUPPORTED_VERSION,
            });
        }
        Ok(Self {
            runtime,
            cell: Mutex::new(client),
        })
    }

    /// Whether this login can modify or delete audit rows - which would defeat append-only.
    ///
    /// # Errors
    ///
    /// SQL failures.
    pub fn over_privileged(&self) -> Result<bool> {
        let mut guard = self.lock();
        let client = &mut *guard;
        self.runtime.block_on(async {
            let row = client
                .query_one(
                    "SELECT
                         COALESCE((SELECT rolsuper FROM pg_roles WHERE rolname = current_user), false),
                         COALESCE(has_table_privilege('events', 'UPDATE'), false),
                         COALESCE(has_table_privilege('events', 'DELETE'), false);",
                    &[],
                )
                .await?;
            let is_super: bool = row.try_get(0).map_err(Error::Db)?;
            let can_update: bool = row.try_get(1).map_err(Error::Db)?;
            let can_delete: bool = row.try_get(2).map_err(Error::Db)?;
            Ok::<_, Error>(is_super || can_update || can_delete)
        })
    }

    /// Creates-or-updates a login and adds it to `remotino_user`. Admin rights required.
    /// `login` and `database` must be pre-validated identifiers (see
    /// [`crate::config::validate_identifier`]); the password is single-quote escaped
    /// defensively even though [`crate::provision`]'s generator never emits a quote.
    pub(crate) fn run_provisioning(&self, login: &str, password: &str, database: &str) -> Result<()> {
        let escaped = password.replace('\'', "''");
        let mut guard = self.lock();
        let client = &mut *guard;
        self.runtime.block_on(async {
            let exists = client
                .query_opt("SELECT 1 FROM pg_roles WHERE rolname::text = $1;", &[&login])
                .await?
                .is_some();
            let role_stmt = if exists {
                format!("ALTER ROLE \"{login}\" WITH LOGIN PASSWORD '{escaped}';")
            } else {
                format!("CREATE ROLE \"{login}\" WITH LOGIN PASSWORD '{escaped}';")
            };
            client.batch_execute(&role_stmt).await?;
            client
                .batch_execute(&format!("GRANT remotino_user TO \"{login}\";"))
                .await?;
            client
                .batch_execute(&format!(
                    "GRANT CONNECT ON DATABASE \"{database}\" TO \"{login}\";"
                ))
                .await?;
            Ok::<_, Error>(())
        })
    }

    /// Drops a provisioned login. Admin rights required. The user's signed audit history is
    /// immutable and stays; only their ability to connect ends.
    ///
    /// # Errors
    ///
    /// A bad identifier, or SQL failures (e.g. the role still owns objects).
    pub fn deprovision_login(&self, login: &str) -> Result<()> {
        validate_identifier(login)?;
        let mut guard = self.lock();
        let client = &mut *guard;
        self.runtime.block_on(async {
            let exists = client
                .query_opt("SELECT 1 FROM pg_roles WHERE rolname::text = $1;", &[&login])
                .await?
                .is_some();
            if exists {
                // DROP OWNED BY first: a role can't be dropped while it still holds privileges
                // (e.g. CONNECT on the database). This revokes them and drops owned objects.
                client
                    .batch_execute(&format!("DROP OWNED BY \"{login}\"; DROP ROLE \"{login}\";"))
                    .await?;
            }
            Ok::<_, Error>(())
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Client> {
        self.cell.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Runs a raw statement, returning rows affected. Test support only - used to prove the
    /// append-only trigger rejects `UPDATE`/`DELETE`. Not for ordinary use.
    ///
    /// # Errors
    ///
    /// SQL failures - including the append-only trigger raising, which is the point.
    #[doc(hidden)]
    pub fn execute_raw_for_tests(&self, sql: &str) -> Result<u64> {
        let mut guard = self.lock();
        let client = &mut *guard;
        self.runtime
            .block_on(async { Ok::<_, Error>(client.execute(sql, &[]).await?) })
    }
}

/// Creates the target database if it does not exist, by connecting to the `postgres`
/// maintenance database. Requires a login with `CREATEDB`. Idempotent.
///
/// # Errors
///
/// Connection failures, or insufficient rights.
pub fn ensure_database(config: &PgConfig) -> Result<()> {
    let name = validate_identifier(&config.database)?.to_owned();
    let runtime = new_runtime()?;
    runtime.block_on(async {
        let client = connect_client(config, "postgres").await?;
        let exists = client
            .query_opt("SELECT 1 FROM pg_database WHERE datname = $1;", &[&name])
            .await?
            .is_some();
        if !exists {
            // CREATE DATABASE cannot run in a transaction or be parameterised; the name was
            // validated as a strict identifier above.
            client
                .batch_execute(&format!("CREATE DATABASE \"{name}\";"))
                .await?;
        }
        Ok::<_, Error>(())
    })
}

/// Drops the target database, forcibly closing other connections first. Idempotent.
///
/// **Destructive** - erases the entire shared repository. For the "start clean" path;
/// recreate with [`ensure_database`] + [`PgRepo::connect_and_migrate`].
///
/// # Errors
///
/// Connection failures, or insufficient rights.
pub fn drop_database(config: &PgConfig) -> Result<()> {
    let name = validate_identifier(&config.database)?.to_owned();
    let runtime = new_runtime()?;
    runtime.block_on(async {
        let client = connect_client(config, "postgres").await?;
        // WITH (FORCE) terminates other sessions (Postgres 13+).
        client
            .batch_execute(&format!("DROP DATABASE IF EXISTS \"{name}\" WITH (FORCE);"))
            .await?;
        Ok::<_, Error>(())
    })
}

impl Repository for PgRepo {
    fn append(&mut self, entries: &[Entry]) -> remotino_crypto::Result<Head> {
        // The chain rules (genesis, contiguity, links) are the client's own - SQL cannot
        // express them - and `MemoryRepo` is the contract both backends answer to.
        let head = validate_batch(self.head()?, entries)?;

        let mut guard = self.lock();
        let client = &mut *guard;
        self.runtime
            .block_on(async {
                // One transaction, so a partial batch cannot land.
                let tx = client.transaction().await?;
                for entry in entries {
                    let body = entry.to_bytes()?;
                    let digest = entry.digest()?;
                    let seq = i64::try_from(entry.body.seq).map_err(|_| Error::MalformedRow {
                        seq: -1,
                        reason: "sequence exceeds i64",
                    })?;
                    // Copy the fixed-size hashes so the params outlive the await cleanly.
                    let prev = entry.body.prev.0;
                    let entry_hash = digest.0;
                    let actor = entry.body.actor.0 .0;
                    let signature = entry.signature;
                    let (prev, entry_hash, actor, signature, body) = (
                        prev.as_slice(),
                        entry_hash.as_slice(),
                        actor.as_slice(),
                        signature.as_slice(),
                        body.as_slice(),
                    );
                    tx.execute(
                        "INSERT INTO events
                             (seq, prev_hash, entry_hash, actor, signature, body)
                         VALUES ($1, $2, $3, $4, $5, $6);",
                        &[&seq, &prev, &entry_hash, &actor, &signature, &body],
                    )
                    .await?;
                }
                tx.commit().await?;
                Ok::<_, Error>(())
            })
            .map_err(to_crypto_err)?;

        Ok(head)
    }

    fn read_from(&self, after: Option<Seq>) -> remotino_crypto::Result<Vec<Entry>> {
        let mut guard = self.lock();
        let client = &mut *guard;

        // ORDER BY is contractual: `verify_chain` walks the slice in order.
        let rows = self
            .runtime
            .block_on(async {
                match after {
                    None => Ok::<_, Error>(
                        client
                            .query("SELECT seq, body FROM events ORDER BY seq ASC;", &[])
                            .await?,
                    ),
                    Some(seq) => {
                        let seq = i64::try_from(seq).map_err(|_| Error::MalformedRow {
                            seq: -1,
                            reason: "cursor exceeds i64",
                        })?;
                        Ok(client
                            .query(
                                "SELECT seq, body FROM events WHERE seq > $1 ORDER BY seq ASC;",
                                &[&seq],
                            )
                            .await?)
                    }
                }
            })
            .map_err(to_crypto_err)?;

        let mut entries = Vec::with_capacity(rows.len());
        for row in rows {
            let seq: i64 = row.try_get(0).map_err(|_| {
                to_crypto_err(Error::MalformedRow {
                    seq: -1,
                    reason: "seq column unreadable",
                })
            })?;
            let body: Vec<u8> = row.try_get(1).map_err(|_| {
                to_crypto_err(Error::MalformedRow {
                    seq,
                    reason: "body column unreadable",
                })
            })?;
            // `from_bytes` refuses any non-canonical encoding, so a hand-edited row is
            // rejected here rather than yielding an entry whose digest no longer matches.
            entries.push(Entry::from_bytes(&body)?);
        }
        Ok(entries)
    }

    fn head(&self) -> remotino_crypto::Result<Option<Head>> {
        let mut guard = self.lock();
        let client = &mut *guard;

        let row = self
            .runtime
            .block_on(async {
                Ok::<_, Error>(
                    client
                        .query_opt(
                            "SELECT seq, entry_hash FROM events ORDER BY seq DESC LIMIT 1;",
                            &[],
                        )
                        .await?,
                )
            })
            .map_err(to_crypto_err)?;

        let Some(row) = row else { return Ok(None) };

        let raw_seq: i64 = row.try_get(0).map_err(|_| {
            to_crypto_err(Error::MalformedRow {
                seq: -1,
                reason: "seq column unreadable",
            })
        })?;
        let digest_bytes: Vec<u8> = row.try_get(1).map_err(|_| {
            to_crypto_err(Error::MalformedRow {
                seq: raw_seq,
                reason: "entry_hash column unreadable",
            })
        })?;
        let digest: [u8; 32] = digest_bytes.as_slice().try_into().map_err(|_| {
            to_crypto_err(Error::MalformedRow {
                seq: raw_seq,
                reason: "entry_hash was not 32 bytes",
            })
        })?;
        let seq = u64::try_from(raw_seq).map_err(|_| {
            to_crypto_err(Error::MalformedRow {
                seq: raw_seq,
                reason: "negative sequence",
            })
        })?;

        Ok(Some(Head {
            seq,
            digest: Digest(digest),
        }))
    }
}

/// Validates a batch against the current head, returning the resulting head. Mirrors
/// `MemoryRepo::append` exactly; duplicated so the crypto crate needs no dependency on this
/// one, and a divergence shows up immediately in conformance tests.
fn validate_batch(current: Option<Head>, entries: &[Entry]) -> remotino_crypto::Result<Head> {
    use remotino_crypto::Error as CryptoError;

    if entries.is_empty() {
        return Err(CryptoError::ChainIntegrity("empty append"));
    }
    let mut head = current;
    for entry in entries {
        match head {
            None => {
                if entry.body.seq != 0 || entry.body.prev != Digest::ZERO {
                    return Err(CryptoError::ChainIntegrity(
                        "append does not start at genesis on an empty repository",
                    ));
                }
            }
            Some(h) => {
                let next = h
                    .seq
                    .checked_add(1)
                    .ok_or(CryptoError::ChainIntegrity("sequence overflow"))?;
                if entry.body.seq != next {
                    return Err(CryptoError::ChainIntegrity("append leaves a sequence gap"));
                }
                if entry.body.prev != h.digest {
                    return Err(CryptoError::ChainIntegrity("append breaks the hash link"));
                }
            }
        }
        head = Some(Head {
            seq: entry.body.seq,
            digest: entry.digest()?,
        });
    }
    head.ok_or(CryptoError::ChainIntegrity("append produced an empty chain"))
}

/// Collapses a backend error into the crypto crate's error type at the trait boundary.
fn to_crypto_err(e: Error) -> remotino_crypto::Error {
    match e {
        Error::Crypto(inner) => inner,
        Error::MalformedRow { .. } => remotino_crypto::Error::Malformed("malformed stored row"),
        Error::SchemaTooNew { .. } => remotino_crypto::Error::Unsupported("schema version"),
        _ => remotino_crypto::Error::Encoding("postgres backend failure"),
    }
}
