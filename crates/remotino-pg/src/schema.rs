//! Schema creation and migration for Postgres.
//!
//! Forward-only, idempotent steps, mirroring the SQL Server schema. The append-only
//! guarantee is enforced two ways: ordinary `remotino_user` logins are granted only
//! `SELECT`/`INSERT` on `events`, and a statement trigger raises on any `UPDATE`/`DELETE`/
//! `TRUNCATE` - so even the table owner cannot rewrite the log in place (only dropping the
//! whole database, which is the explicit "reset" path, gets rid of it).

use crate::repo::Client;
use crate::{Error, Result};

/// Schema version this build implements.
pub const SUPPORTED_VERSION: i32 = 1;

/// Migration steps, applied in order. Each is idempotent on its own.
const MIGRATIONS: &[&str] = &[
    // 0001 schema_version
    "CREATE TABLE IF NOT EXISTS schema_version (
         version    integer     PRIMARY KEY,
         applied_at timestamptz NOT NULL DEFAULT now()
     );",
    // 0002 events (the append-only audit chain)
    "CREATE TABLE IF NOT EXISTS events (
         seq        bigint      PRIMARY KEY,
         prev_hash  bytea       NOT NULL,
         entry_hash bytea       NOT NULL,
         actor      bytea       NOT NULL,
         signature  bytea       NOT NULL,
         body       bytea       NOT NULL,
         written_at timestamptz NOT NULL DEFAULT now()
     );",
    // 0003 unique entry-hash index
    "CREATE UNIQUE INDEX IF NOT EXISTS ix_events_entry_hash ON events (entry_hash);",
    // 0004 identities directory
    "CREATE TABLE IF NOT EXISTS identities (
         key_id      bytea PRIMARY KEY,
         public_blob bytea NOT NULL
     );",
    // 0005 vaults
    "CREATE TABLE IF NOT EXISTS vaults (
         key_id      bytea PRIMARY KEY,
         sealed_blob bytea NOT NULL
     );",
    // 0006 least-privilege role
    "DO $$ BEGIN
         CREATE ROLE remotino_user;
     EXCEPTION WHEN duplicate_object THEN NULL;
     END $$;",
    // 0007 grants: SELECT/INSERT only on the append-only tables. No UPDATE/DELETE is granted,
    // so an ordinary login simply cannot rewrite history - the whole reason for the backend.
    "GRANT SELECT, INSERT ON events        TO remotino_user;
     GRANT SELECT, INSERT ON identities    TO remotino_user;
     GRANT SELECT, INSERT, UPDATE ON vaults TO remotino_user;
     GRANT SELECT ON schema_version        TO remotino_user;",
    // 0008 append-only trigger: block UPDATE/DELETE/TRUNCATE on events for everyone, so even a
    // table owner or a mistaken over-privileged login cannot rewrite the log in place.
    "CREATE OR REPLACE FUNCTION remotino_events_append_only() RETURNS trigger
         LANGUAGE plpgsql AS $$
     BEGIN
         RAISE EXCEPTION 'events is append-only; UPDATE/DELETE/TRUNCATE is not permitted';
     END $$;",
    "DROP TRIGGER IF EXISTS events_append_only ON events;",
    "CREATE TRIGGER events_append_only
         BEFORE UPDATE OR DELETE OR TRUNCATE ON events
         FOR EACH STATEMENT EXECUTE FUNCTION remotino_events_append_only();",
];

/// Applies every migration step, then records [`SUPPORTED_VERSION`]. Safe to run repeatedly.
///
/// # Errors
///
/// [`Error::SchemaTooNew`] if the database reports a newer version; otherwise SQL failures.
pub(crate) async fn migrate(client: &Client) -> Result<()> {
    // Serialise concurrent migrations with a session advisory lock (arbitrary fixed key).
    client
        .batch_execute("SELECT pg_advisory_lock(4919);")
        .await?;
    let result = migrate_locked(client).await;
    let _ = client.batch_execute("SELECT pg_advisory_unlock(4919);").await;
    result
}

async fn migrate_locked(client: &Client) -> Result<()> {
    // The version table must exist before it can be read.
    if let Some(first) = MIGRATIONS.first() {
        client.batch_execute(first).await?;
    }
    if let Some(found) = current_version(client).await?
        && found > SUPPORTED_VERSION
    {
        return Err(Error::SchemaTooNew {
            found,
            supported: SUPPORTED_VERSION,
        });
    }
    for step in MIGRATIONS.iter().skip(1) {
        client.batch_execute(step).await?;
    }
    client
        .execute(
            "INSERT INTO schema_version (version) VALUES ($1) ON CONFLICT DO NOTHING;",
            &[&SUPPORTED_VERSION],
        )
        .await?;
    Ok(())
}

/// Reads the highest recorded schema version, or `None` if nothing is recorded yet.
pub(crate) async fn current_version(client: &Client) -> Result<Option<i32>> {
    let row = client
        .query_opt("SELECT max(version) FROM schema_version;", &[])
        .await?;
    match row {
        Some(r) => Ok(r.try_get::<_, Option<i32>>(0).map_err(Error::Db)?),
        None => Ok(None),
    }
}
