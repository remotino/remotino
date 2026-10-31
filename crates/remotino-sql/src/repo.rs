//! [`Repository`] over SQL Server.

use remotino_crypto::chain::{Entry, Head, Seq};
use remotino_crypto::repository::Repository;
use remotino_crypto::Digest;
use tiberius::Config;
use tokio::net::TcpStream;
use tokio_util::compat::{Compat, TokioAsyncWriteCompatExt as _};

use crate::schema;
use crate::{Error, Result, SqlConfig};

pub(crate) type Client = tiberius::Client<Compat<TcpStream>>;

/// An append-only chain store backed by SQL Server.
///
/// Owns a current-thread Tokio runtime; see the crate docs for why, and for the
/// constraint that comes with it.
pub struct SqlRepo {
    runtime: tokio::runtime::Runtime,
    /// `Repository::read_from` and `head` take `&self` by contract - they are cheap and
    /// callable while the repo is held immutably - but tiberius needs `&mut` to issue a
    /// query. A mutex is the honest reconciliation. Contention is not a concern: a
    /// `SqlRepo` owns one connection and is used from one thread at a time.
    cell: std::sync::Mutex<Client>,
}

impl core::fmt::Debug for SqlRepo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never render the client: its config carries a password when SQL auth is used.
        f.write_str("SqlRepo { .. }")
    }
}

fn new_runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(Error::Runtime)
}

impl SqlRepo {
    /// Connects and applies any outstanding migrations.
    ///
    /// Requires rights an ordinary `remotino_user` login does not have. Clients should
    /// use [`SqlRepo::connect`] only when acting as an administrator; everyday sessions
    /// use [`SqlRepo::connect_checked`].
    ///
    /// # Errors
    ///
    /// Connection, TLS, and migration failures.
    pub fn connect_and_migrate(config: &SqlConfig) -> Result<Self> {
        let runtime = new_runtime()?;
        let mut client = runtime.block_on(connect_client(config.to_tiberius()))?;
        runtime.block_on(schema::migrate(&mut client))?;
        Ok(Self {
            runtime,
            cell: std::sync::Mutex::new(client),
        })
    }

    /// Connects without migrating, verifying the schema is one this build understands.
    ///
    /// Ordinary users hold `SELECT`/`INSERT` and nothing more, so attempting migration
    /// would fail on permissions. Checking up front means a version mismatch surfaces at
    /// connect time rather than mid-append.
    ///
    /// # Errors
    ///
    /// Connection failures, or [`Error::SchemaTooNew`].
    pub fn connect_checked(config: &SqlConfig) -> Result<Self> {
        let runtime = new_runtime()?;
        let mut client = runtime.block_on(connect_client(config.to_tiberius()))?;
        if let Some(found) = runtime.block_on(schema::current_version(&mut client))?
            && found > schema::SUPPORTED_VERSION
        {
            return Err(Error::SchemaTooNew {
                found,
                supported: schema::SUPPORTED_VERSION,
            });
        }
        Ok(Self {
            runtime,
            cell: std::sync::Mutex::new(client),
        })
    }

    /// Deletes every row. Test support only.
    ///
    /// Needs rights an ordinary client does not have - `DENY DELETE` is precisely the
    /// point - so this only works as an admin against a scratch database.
    ///
    /// # Errors
    ///
    /// SQL failures.
    #[doc(hidden)]
    pub fn truncate_for_tests(&mut self) -> Result<()> {
        let mut guard = self.lock();
        let client = &mut *guard;
        self.runtime.block_on(async {
            client.execute("DELETE FROM dbo.Events;", &[]).await?;
            Ok::<_, Error>(())
        })
    }

    /// Locks the connection, recovering from a poisoned mutex.
    ///
    /// Poisoning here means a previous call panicked mid-query. The connection may be
    /// mid-protocol, but the alternative - refusing to work at all - is worse for a
    /// single-connection client, and any real protocol desync surfaces as a tiberius
    /// error on the next call.
    fn lock(&self) -> std::sync::MutexGuard<'_, Client> {
        self.cell.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Runs an async closure against the locked client, blocking on the owned runtime.
    ///
    /// The one bridge between this crate's sync surface and tiberius's async API. The
    /// sibling modules (`directory`, `provision`) go through here rather than reaching
    /// into the private `runtime`/`cell` fields, so the blocking-context caveat lives in
    /// exactly one place.
    ///
    /// The closure returns a boxed future. A plain `-> impl Future` cannot express the
    /// higher-ranked bound "the future borrows the client for as long as it runs" on
    /// stable Rust, so the box is the price of a clean sync facade over an async driver.
    pub(crate) fn with_client<T, F>(&self, f: F) -> Result<T>
    where
        F: for<'a> FnOnce(
            &'a mut Client,
        ) -> std::pin::Pin<
            Box<dyn core::future::Future<Output = Result<T>> + 'a>,
        >,
    {
        let mut guard = self.lock();
        self.runtime.block_on(f(&mut guard))
    }
}

async fn connect_client(config: Config) -> Result<Client> {
    let tcp = TcpStream::connect(config.get_addr())
        .await
        .map_err(Error::Connect)?;
    // Nagle off: this is a request/response protocol, and coalescing small writes just
    // adds latency to every round trip.
    tcp.set_nodelay(true).map_err(Error::Connect)?;
    Ok(tiberius::Client::connect(config, tcp.compat_write()).await?)
}

/// Creates the target database if it does not exist, by connecting to `master`.
///
/// Requires a login with `CREATE DATABASE` rights (an administrator). Idempotent, so it is
/// safe to call every time an admin points the app at a server - it does nothing if the
/// database is already there. `connect_and_migrate` then sets up the schema inside it.
///
/// # Errors
///
/// Connection failures, or insufficient rights to create the database.
pub fn ensure_database(config: &SqlConfig) -> Result<()> {
    let runtime = new_runtime()?;
    let mut master = config.to_tiberius();
    master.database("master");
    let db = config.database.clone();
    runtime.block_on(async {
        let mut client = connect_client(master).await?;
        // A database name can't be a bound parameter, and parameterizing QUOTENAME through
        // tiberius trips the parser. Escape the name for both contexts ourselves: single
        // quotes for the DB_ID literal, `]` for the bracket-quoted identifier. Run the
        // CREATE via EXEC so it isn't subject to the "must be first in batch" rule.
        let name_lit = db.replace('\'', "''");
        let name_ident = db.replace(']', "]]");
        let sql = format!(
            "IF DB_ID(N'{name_lit}') IS NULL EXEC('CREATE DATABASE [{name_ident}]');"
        );
        client.simple_query(sql).await?;
        Ok::<_, Error>(())
    })?;
    Ok(())
}

/// Drops the target database, forcibly closing any other connections to it first.
///
/// Connects to `master` (so it is not itself holding the database open) and, if the database
/// exists, sets it single-user with `ROLLBACK IMMEDIATE` to evict live sessions, then drops
/// it. Idempotent: a no-op if the database is already gone. Requires an administrator.
///
/// **Destructive.** This erases the entire shared repository - every event, identity and
/// grant. It exists for "start clean" during setup/testing; recreate with
/// [`ensure_database`] + [`SqlRepo::connect_and_migrate`].
///
/// # Errors
///
/// Connection failures, or insufficient rights to drop the database.
pub fn drop_database(config: &SqlConfig) -> Result<()> {
    let runtime = new_runtime()?;
    let mut master = config.to_tiberius();
    master.database("master");
    let name_lit = config.database.replace('\'', "''");
    let name_ident = config.database.replace(']', "]]");
    runtime.block_on(async {
        let mut client = connect_client(master).await?;
        let sql = format!(
            "IF DB_ID(N'{name_lit}') IS NOT NULL
             BEGIN
                 ALTER DATABASE [{name_ident}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
                 DROP DATABASE [{name_ident}];
             END"
        );
        client.simple_query(sql).await?;
        Ok::<_, Error>(())
    })?;
    Ok(())
}

/// What a connecting login is allowed to do to the audit table, relative to the
/// least-privilege set the append-only guarantee depends on.
#[derive(Debug, Clone, Copy)]
pub struct Privileges {
    /// The login is a `sysadmin`. Sysadmin bypasses every permission check - including the
    /// `DENY UPDATE, DELETE` that makes the log tamper-evident - so history is not protected.
    pub is_sysadmin: bool,
    /// The login can `UPDATE` rows in `dbo.Events` (it could rewrite history).
    pub can_update: bool,
    /// The login can `DELETE` rows in `dbo.Events` (it could erase history).
    pub can_delete: bool,
}

impl Privileges {
    /// True if the login has more than the read/append rights Remotino relies on, so the
    /// server-enforced append-only guarantee does not actually hold for it.
    #[must_use]
    pub fn over_privileged(&self) -> bool {
        self.is_sysadmin || self.can_update || self.can_delete
    }
}

/// Asks SQL Server whether *this* login can modify or delete audit rows - which would defeat
/// the append-only guarantee (`DESIGN.md` 3). Connects with the given config and reads the
/// login's own effective permissions; no special rights are needed to ask.
///
/// # Errors
///
/// Connection failures.
pub fn check_privileges(config: &SqlConfig) -> Result<Privileges> {
    let runtime = new_runtime()?;
    runtime.block_on(async {
        let mut client = connect_client(config.to_tiberius()).await?;
        let row = client
            .query(
                "SELECT
                     CAST(ISNULL(IS_SRVROLEMEMBER('sysadmin'), 0) AS INT),
                     CAST(ISNULL(HAS_PERMS_BY_NAME('dbo.Events', 'OBJECT', 'UPDATE'), 0) AS INT),
                     CAST(ISNULL(HAS_PERMS_BY_NAME('dbo.Events', 'OBJECT', 'DELETE'), 0) AS INT);",
                &[],
            )
            .await?
            .into_row()
            .await?;
        let get = |i: usize| row.as_ref().and_then(|r| r.get::<i32, _>(i)).unwrap_or(0) != 0;
        Ok(Privileges {
            is_sysadmin: get(0),
            can_update: get(1),
            can_delete: get(2),
        })
    })
}

impl Repository for SqlRepo {
    fn append(&mut self, entries: &[Entry]) -> remotino_crypto::Result<Head> {
        // Structural validation happens here rather than in the database: the rules are
        // the chain's own (genesis, contiguity, links), which SQL cannot express, and
        // `MemoryRepo` is the contract both backends answer to.
        let head = validate_batch(self.head()?, entries)?;

        let mut guard = self.lock();
        let client = &mut *guard;
        self.runtime
            .block_on(async {
                // One transaction, so a partial batch cannot land. A half-written append
                // would leave a head disagreeing with the rows behind it.
                client.simple_query("BEGIN TRANSACTION;").await?;

                for entry in entries {
                    let body = entry.to_bytes()?;
                    let digest = entry.digest()?;
                    let seq = i64::try_from(entry.body.seq).map_err(|_| Error::MalformedRow {
                        seq: -1,
                        reason: "sequence exceeds i64",
                    })?;

                    client
                        .execute(
                            "INSERT INTO dbo.Events
                                 (seq, prev_hash, entry_hash, actor, signature, body)
                             VALUES (@P1, @P2, @P3, @P4, @P5, @P6);",
                            &[
                                &seq,
                                &entry.body.prev.0.as_slice(),
                                &digest.0.as_slice(),
                                &entry.body.actor.0 .0.as_slice(),
                                &entry.signature.as_slice(),
                                &body.as_slice(),
                            ],
                        )
                        .await?;
                }

                client.simple_query("COMMIT TRANSACTION;").await?;
                Ok::<_, Error>(())
            })
            .map_err(to_crypto_err)?;

        Ok(head)
    }

    fn read_from(&self, after: Option<Seq>) -> remotino_crypto::Result<Vec<Entry>> {
        let mut guard = self.lock();
        let client = &mut *guard;

        // ORDER BY is contractual, not incidental: `verify_chain` walks the slice in
        // order, so a backend returning rows in storage order would fail verification on
        // a perfectly good chain.
        let rows = self
            .runtime
            .block_on(async {
                let stream = match after {
                    None => {
                        client
                            .query("SELECT seq, body FROM dbo.Events ORDER BY seq ASC;", &[])
                            .await?
                    }
                    Some(seq) => {
                        let seq = i64::try_from(seq).map_err(|_| Error::MalformedRow {
                            seq: -1,
                            reason: "cursor exceeds i64",
                        })?;
                        client
                            .query(
                                "SELECT seq, body FROM dbo.Events
                                 WHERE seq > @P1 ORDER BY seq ASC;",
                                &[&seq],
                            )
                            .await?
                    }
                };
                Ok::<_, Error>(stream.into_first_result().await?)
            })
            .map_err(to_crypto_err)?;

        let mut entries = Vec::with_capacity(rows.len());
        for row in rows {
            let seq: i64 = row.get(0).unwrap_or(-1);
            let body: &[u8] = row.get(1).ok_or_else(|| {
                to_crypto_err(Error::MalformedRow {
                    seq,
                    reason: "body column was null",
                })
            })?;

            // Decoding through `from_bytes` is what makes the storage contract hold: it
            // refuses any encoding not byte-identical to the canonical one, so a row
            // hand-edited into a non-canonical alias is rejected here rather than
            // silently yielding an entry whose digest no longer matches its bytes.
            entries.push(Entry::from_bytes(body)?);
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
                        .query(
                            "SELECT TOP 1 seq, entry_hash FROM dbo.Events ORDER BY seq DESC;",
                            &[],
                        )
                        .await?
                        .into_row()
                        .await?,
                )
            })
            .map_err(to_crypto_err)?;

        let Some(row) = row else { return Ok(None) };

        let raw_seq: i64 = row.get(0).unwrap_or(-1);
        let digest_bytes: &[u8] = row.get(1).ok_or_else(|| {
            to_crypto_err(Error::MalformedRow {
                seq: raw_seq,
                reason: "entry_hash column was null",
            })
        })?;
        let digest: [u8; 32] = digest_bytes.try_into().map_err(|_| {
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

/// Validates a batch against the current head, returning the resulting head.
///
/// Mirrors `MemoryRepo::append` exactly. Duplicated rather than shared because the crypto
/// crate must not gain a dependency on this one, and the contract is small enough that a
/// divergence shows up immediately in the conformance tests.
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

/// Collapses a backend error into the crypto crate's error type.
///
/// Lossy on purpose at the trait boundary - `Repository` returns
/// `remotino_crypto::Result`, and the crypto crate must not know about SQL. Callers
/// needing the detail use the inherent methods, which return [`crate::Error`].
fn to_crypto_err(e: Error) -> remotino_crypto::Error {
    match e {
        Error::Crypto(inner) => inner,
        Error::MalformedRow { .. } => remotino_crypto::Error::Malformed("malformed stored row"),
        Error::SchemaTooNew { .. } => remotino_crypto::Error::Unsupported("schema version"),
        _ => remotino_crypto::Error::Encoding("sql backend failure"),
    }
}
