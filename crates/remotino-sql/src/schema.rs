//! Schema creation and migration.
//!
//! Migrations are forward-only and idempotent: each step checks for its own effect before
//! applying it, so running twice is harmless and a half-applied run can be resumed. There
//! is no `down` path - this is an append-only audit store, and a migration that could
//! drop columns is a migration that could destroy history.
//!
//! # Who runs this
//!
//! Not ordinary clients. Creating tables and roles needs rights a `remotino_user` login
//! deliberately does not have, so migration runs under the admin credential the
//! provisioning wizard holds transiently (`DESIGN.md` 3). An ordinary client that finds
//! an out-of-date schema should report it, not try to fix it.

use crate::{Error, Result};

/// Schema version this build implements.
///
/// Bump when adding a migration step. A database reporting a *higher* version is refused
/// rather than tolerated: silently ignoring unknown columns would let this client append
/// entries a newer peer wrote assumptions about.
pub const SUPPORTED_VERSION: i32 = 1;

/// The migration steps, applied in order.
///
/// Each is idempotent on its own. Kept as literal SQL rather than generated, because this
/// is the security boundary of the whole system - `DENY UPDATE, DELETE` on `Events` is
/// the reason the project uses SQL Server at all, and it should be readable at a glance
/// rather than assembled by a builder.
const MIGRATIONS: &[(&str, &str)] = &[
    (
        "0001_schema_version",
        r"
IF OBJECT_ID('dbo.SchemaVersion') IS NULL
CREATE TABLE dbo.SchemaVersion (
    version     INT           NOT NULL PRIMARY KEY,
    applied_at  DATETIME2     NOT NULL DEFAULT SYSUTCDATETIME()
);
",
    ),
    (
        "0002_events",
        r"
IF OBJECT_ID('dbo.Events') IS NULL
CREATE TABLE dbo.Events (
    seq         BIGINT         NOT NULL PRIMARY KEY,
    prev_hash   BINARY(32)     NOT NULL,
    entry_hash  BINARY(32)     NOT NULL,
    actor       BINARY(32)     NOT NULL,
    signature   BINARY(64)     NOT NULL,
    body        VARBINARY(MAX) NOT NULL,
    written_at  DATETIME2      NOT NULL DEFAULT SYSUTCDATETIME()
);
",
    ),
    (
        "0003_events_hash_index",
        r"
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Events_entry_hash')
    CREATE UNIQUE INDEX IX_Events_entry_hash ON dbo.Events(entry_hash);
",
    ),
    (
        "0004_identities",
        r"
IF OBJECT_ID('dbo.Identities') IS NULL
CREATE TABLE dbo.Identities (
    key_id      BINARY(32)     NOT NULL PRIMARY KEY,
    public_blob VARBINARY(MAX) NOT NULL
);
",
    ),
    (
        "0005_vaults",
        r"
IF OBJECT_ID('dbo.Vaults') IS NULL
CREATE TABLE dbo.Vaults (
    key_id      BINARY(32)     NOT NULL PRIMARY KEY,
    sealed_blob VARBINARY(MAX) NOT NULL
);
",
    ),
    (
        "0006_role_and_grants",
        r"
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'remotino_user' AND type = 'R')
    CREATE ROLE remotino_user;
",
    ),
    (
        // Split from role creation so re-running repairs grants even if the role exists.
        // A permission silently missing is worse than a permission that is re-granted.
        "0007_grants",
        r"
GRANT SELECT, INSERT ON dbo.Events        TO remotino_user;
DENY  UPDATE, DELETE ON dbo.Events        TO remotino_user;
GRANT SELECT, INSERT ON dbo.Identities    TO remotino_user;
DENY  UPDATE, DELETE ON dbo.Identities    TO remotino_user;
GRANT SELECT, INSERT, UPDATE ON dbo.Vaults TO remotino_user;
-- Read-only on the version table: ordinary clients call connect_checked, which reads it
-- to refuse a schema newer than they understand. Without SELECT here that check fails
-- with a permission error the moment a real per-user login connects - which is exactly
-- how this grant came to be added. No INSERT: only migration (admin) writes it.
GRANT SELECT ON dbo.SchemaVersion         TO remotino_user;
DENY  INSERT, UPDATE, DELETE ON dbo.SchemaVersion TO remotino_user;
",
    ),
];

/// Applies every migration step, then records [`SUPPORTED_VERSION`].
///
/// Safe to run repeatedly.
///
/// # Errors
///
/// [`Error::SchemaTooNew`] if the database reports a newer version than this build
/// supports; otherwise propagates SQL failures.
pub(crate) async fn migrate(client: &mut crate::repo::Client) -> Result<()> {
    // Idempotent is not the same as concurrency-safe. Every step is `IF NOT EXISTS ...
    // CREATE ...`, which is check-then-act: two clients connecting to a fresh database at
    // the same moment both see nothing, both create, and the loser gets
    // "There is already an object named 'SchemaVersion'". That is not hypothetical - it
    // is exactly what eight parallel integration tests did on the first run.
    //
    // `sp_getapplock` serialises migration across connections. Session-scoped so it spans
    // all the statements below rather than a single transaction, and released explicitly
    // at the end (SQL Server also drops it when the session closes, which covers a client
    // that dies mid-migration).
    let lock = client
        .query(
            "DECLARE @rc INT;
             EXEC @rc = sp_getapplock @Resource = 'remotino_schema_migration',
                                      @LockMode = 'Exclusive',
                                      @LockOwner = 'Session',
                                      @LockTimeout = 30000;
             SELECT @rc;",
            &[],
        )
        .await?
        .into_row()
        .await?;

    // Negative return codes mean the lock was not granted: -1 timeout, -2 cancelled,
    // -3 deadlock victim. Proceeding anyway would reintroduce the race we just closed.
    if lock.and_then(|r| r.get::<i32, _>(0)).unwrap_or(-1) < 0 {
        return Err(Error::MigrationLock);
    }

    let result = migrate_locked(client).await;

    // Release even if migration failed - otherwise the lock survives for the life of the
    // connection and the next attempt on this session blocks forever.
    let _ = client
        .simple_query(
            "EXEC sp_releaseapplock @Resource = 'remotino_schema_migration',
                                    @LockOwner = 'Session';",
        )
        .await;

    result
}

async fn migrate_locked(client: &mut crate::repo::Client) -> Result<()> {
    // The version table has to exist before it can be read, so step one runs first and
    // unconditionally.
    if let Some((_, sql)) = MIGRATIONS.first() {
        client.simple_query(*sql).await?.into_results().await?;
    }

    if let Some(found) = current_version(client).await?
        && found > SUPPORTED_VERSION
    {
        return Err(Error::SchemaTooNew {
            found,
            supported: SUPPORTED_VERSION,
        });
    }

    for (_, sql) in MIGRATIONS.iter().skip(1) {
        client.simple_query(*sql).await?.into_results().await?;
    }

    client
        .execute(
            "IF NOT EXISTS (SELECT 1 FROM dbo.SchemaVersion WHERE version = @P1)
                 INSERT INTO dbo.SchemaVersion (version) VALUES (@P1);",
            &[&SUPPORTED_VERSION],
        )
        .await?;

    Ok(())
}

/// Reads the highest recorded schema version, or `None` if nothing is recorded yet.
pub(crate) async fn current_version(client: &mut crate::repo::Client) -> Result<Option<i32>> {
    let row = client
        .query("SELECT MAX(version) FROM dbo.SchemaVersion;", &[])
        .await?
        .into_row()
        .await?;
    Ok(row.and_then(|r| r.get::<i32, _>(0)))
}
