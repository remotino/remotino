//! Remotino desktop app: the Tauri bridge between the Svelte UI and the Rust backend.
//!
//! Everything security-sensitive stays on this side. The webview never sees a private key
//! or a plaintext credential - it sends a passphrase in and receives a decrypted
//! projection out. The unlocked [`Identity`] and the open [`Session`] (which holds the
//! folder content keys) live only in this process's memory, never serialised to the
//! frontend.

mod known_hosts;
mod profile;
mod rdp;
mod session;
mod ssh;
mod threaded_repo;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;

use remotino_crypto::identity::{Identity, KeyId, PublicIdentity, SealedIdentity};
use remotino_crypto::kdf::KdfParams;
use remotino_crypto::Digest;
use remotino_model::ids::{CredentialId, EntryId, FolderId, ID_LEN};
use remotino_model::projection::{Connection, ConnectionKind, Credential, CredentialSecret, Projection};
use remotino_model::structure::Structure;
use serde::Serialize;
use session::Session;
use tauri::{Manager, State};

/// Process-lifetime state. The identity and session are the crown jewels: they never leave
/// this struct, and a lock clears them.
struct AppState {
    identity: Mutex<Option<Identity>>,
    session: Mutex<Option<Session>>,
    identity_path: Mutex<Option<PathBuf>>,
    store_path: Mutex<Option<PathBuf>>,
    /// Path to the RDP known-hosts (TOFU cert pins) file.
    known_hosts_path: Mutex<Option<PathBuf>>,
    /// Path to the connection-profile (which backend) file.
    profile_path: Mutex<Option<PathBuf>>,
    /// Path to this machine's chosen display name (published on self-enrolment).
    name_path: Mutex<Option<PathBuf>>,
    /// Live SSH sessions, keyed by the id the UI assigns each terminal tab.
    ssh: Arc<ssh::Sessions>,
    /// Live RDP sessions (each a sidecar process), keyed the same way.
    rdp: Arc<rdp::Sessions>,
}

impl AppState {
    fn new() -> Self {
        Self {
            identity: Mutex::new(None),
            session: Mutex::new(None),
            identity_path: Mutex::new(None),
            store_path: Mutex::new(None),
            known_hosts_path: Mutex::new(None),
            profile_path: Mutex::new(None),
            name_path: Mutex::new(None),
            ssh: Arc::new(ssh::Sessions::default()),
            rdp: Arc::new(rdp::Sessions::default()),
        }
    }
}

// ---- DTOs: the shapes the Svelte frontend expects (tree.svelte.ts) ----

#[derive(Serialize)]
struct IdentityInfo {
    fingerprint: String,
}

#[derive(Serialize)]
struct IdentityStatus {
    exists: bool,
    fingerprint: Option<String>,
}

#[derive(Serialize)]
struct FolderDto {
    id: String,
    parent: Option<String>,
    name: Option<String>,
    readable: bool,
    /// Granted to at least one user other than me.
    shared: bool,
}

#[derive(Serialize)]
struct ConnectionDto {
    id: String,
    folder: String,
    kind: String,
    name: String,
    host: String,
    port: u16,
    /// Id of the vault credential this connection uses, if any.
    credential: Option<String>,
    /// Whether this connection's folder is shared with another user.
    shared: bool,
}

/// Vault credential as the UI sees it: metadata only. The password or private key never
/// crosses into the webview.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CredentialDto {
    id: String,
    name: String,
    kind: String,
    username: String,
    domain: Option<String>,
    is_key: bool,
    fingerprint: Option<String>,
    /// Granted to at least one user other than me.
    shared: bool,
}

#[derive(Serialize)]
struct TreeDto {
    folders: Vec<FolderDto>,
    connections: Vec<ConnectionDto>,
    credentials: Vec<CredentialDto>,
}

/// An enrolled user as the UI sees them.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UserDto {
    key_id: String,
    name: String,
    fingerprint: String,
    /// Whether this enrolled user is me (so the UI can label it and share modals can skip it).
    is_self: bool,
}

// ---- commands ----

/// Whether an identity exists, and its public-key fingerprint if so (read from the public
/// half stored in the clear - no passphrase needed).
#[tauri::command]
fn identity_status(state: State<'_, AppState>) -> IdentityStatus {
    let Some(path) = state.identity_path.lock().ok().and_then(|p| p.clone()) else {
        return IdentityStatus { exists: false, fingerprint: None };
    };
    if !path.exists() {
        return IdentityStatus { exists: false, fingerprint: None };
    }
    let fingerprint = std::fs::read(&path)
        .ok()
        .and_then(|b| ciborium::from_reader::<SealedIdentity, _>(b.as_slice()).ok())
        .map(|sealed| fingerprint_of(sealed.public.key_id()));
    IdentityStatus { exists: true, fingerprint }
}

/// Creates and unlocks a new identity, then seeds a starter set of example connections so
/// the tree is not empty on first run.
#[tauri::command]
fn create_identity(passphrase: String, state: State<'_, AppState>) -> Result<IdentityInfo, String> {
    let identity = Identity::generate().map_err(stringify)?;
    let sealed = identity
        .seal(&passphrase, KdfParams::default())
        .map_err(stringify)?;

    let path = identity_file(&state)?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let mut buf = Vec::new();
    ciborium::into_writer(&sealed, &mut buf).map_err(|e| e.to_string())?;
    std::fs::write(&path, buf).map_err(|e| e.to_string())?;

    // A new identity starts with an empty tree on whichever backend is configured.
    let mut sess = open_session_for(&state, &identity)?;

    seal_profile_password(&state, &identity);
    self_enroll(&state, &mut sess, &identity);
    let info = IdentityInfo { fingerprint: fingerprint(&identity) };
    *state.identity.lock().map_err(lockerr)? = Some(identity);
    *state.session.lock().map_err(lockerr)? = Some(sess);
    Ok(info)
}

/// Unlocks the persisted identity and opens its store.
///
/// A wrong passphrase and a tampered file return the same opaque failure, so the UI cannot
/// become a passphrase oracle.
#[tauri::command]
fn unlock(passphrase: String, state: State<'_, AppState>) -> Result<IdentityInfo, String> {
    let path = identity_file(&state)?;
    let bytes = std::fs::read(&path).map_err(|_| "no identity found".to_owned())?;
    let sealed: SealedIdentity =
        ciborium::from_reader(bytes.as_slice()).map_err(|_| "identity file unreadable".to_owned())?;
    let identity = sealed.unlock(&passphrase).map_err(|_| "wrong passphrase".to_owned())?;

    let mut session = open_session_for(&state, &identity)?;
    seal_profile_password(&state, &identity);
    self_enroll(&state, &mut session, &identity);
    let info = IdentityInfo { fingerprint: fingerprint(&identity) };
    *state.identity.lock().map_err(lockerr)? = Some(identity);
    *state.session.lock().map_err(lockerr)? = Some(session);
    Ok(info)
}

/// Clears the unlocked identity and session from memory.
#[tauri::command]
fn lock(state: State<'_, AppState>) -> Result<(), String> {
    *state.identity.lock().map_err(lockerr)? = None;
    *state.session.lock().map_err(lockerr)? = None;
    Ok(())
}

/// Wipes this machine's Remotino data - identity, local store, connection profile, host
/// pins, and display name - then restarts to a clean first-run state. Irreversible; the
/// shared SQL database (if any) is untouched. Simulates a fresh install.
#[tauri::command]
fn reset_app(app: tauri::AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    // Drop in-memory secrets before touching disk.
    if let Ok(mut g) = state.identity.lock() {
        *g = None;
    }
    if let Ok(mut g) = state.session.lock() {
        *g = None;
    }
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    for name in [
        "identity.cbor",
        "store.db",
        "store.db-wal",
        "store.db-shm",
        "connection.json",
        "known_hosts.json",
        "display_name.txt",
    ] {
        let _ = std::fs::remove_file(dir.join(name));
    }
    // Never returns - the process re-execs into a clean first run.
    app.restart();
}

/// The current backend selection. Any interim cleartext SQL password is redacted from the
/// response - the webview only learns *that* a password is stored (via `passwordSealed`),
/// never its value.
#[tauri::command]
fn get_connection_profile(state: State<'_, AppState>) -> profile::ConnectionProfile {
    let mut profile = current_profile(&state);
    match &mut profile {
        profile::ConnectionProfile::Sql(sql) => sql.password = None,
        profile::ConnectionProfile::Pg(pg) => pg.password = None,
        profile::ConnectionProfile::Local => {}
    }
    profile
}

/// Saves which backend to use. Takes effect on the next unlock. If an identity is unlocked
/// and a SQL password was supplied, it is sealed to the identity before saving (6c) so it
/// never touches disk in the clear.
#[tauri::command]
fn set_connection_profile(
    mut profile: profile::ConnectionProfile,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let path = state
        .profile_path
        .lock()
        .map_err(lockerr)?
        .clone()
        .ok_or("app data dir unavailable")?;
    let existing = profile::load(&path);
    match &mut profile {
        profile::ConnectionProfile::Sql(sql) => {
            // Preserve an existing password when the user didn't type a new one: the sealed
            // blob, or the interim cleartext if nothing is sealed yet.
            if sql.password.as_deref().unwrap_or("").is_empty() {
                if let profile::ConnectionProfile::Sql(existing) = &existing {
                    sql.password_sealed = existing.password_sealed.clone();
                    if sql.password_sealed.is_none() {
                        sql.password = existing.password.clone();
                    }
                }
            }
            if let Some(identity) = state.identity.lock().map_err(lockerr)?.as_ref() {
                *sql = sql.sealed_to(identity)?;
            }
        }
        profile::ConnectionProfile::Pg(pg) => {
            if pg.password.as_deref().unwrap_or("").is_empty() {
                if let profile::ConnectionProfile::Pg(existing) = &existing {
                    pg.password_sealed = existing.password_sealed.clone();
                    if pg.password_sealed.is_none() {
                        pg.password = existing.password.clone();
                    }
                }
            }
            if let Some(identity) = state.identity.lock().map_err(lockerr)?.as_ref() {
                *pg = pg.sealed_to(identity)?;
            }
        }
        profile::ConnectionProfile::Local => {}
    }
    crate::profile::save(&path, &profile)
}

/// Upgrades an interim cleartext SQL password to the identity-sealed form, if the saved
/// profile still holds one. Called after unlock/create, when the identity first exists.
/// A no-op unless a SQL profile with a cleartext password is on disk.
fn seal_profile_password(state: &State<'_, AppState>, identity: &Identity) {
    let Some(path) = state.profile_path.lock().ok().and_then(|p| p.clone()) else {
        return;
    };
    match profile::load(&path) {
        profile::ConnectionProfile::Sql(sql)
            if sql.password.as_deref().is_some_and(|p| !p.is_empty()) =>
        {
            if let Ok(sealed) = sql.sealed_to(identity) {
                let _ = profile::save(&path, &profile::ConnectionProfile::Sql(sealed));
            }
        }
        profile::ConnectionProfile::Pg(pg)
            if pg.password.as_deref().is_some_and(|p| !p.is_empty()) =>
        {
            if let Ok(sealed) = pg.sealed_to(identity) {
                let _ = profile::save(&path, &profile::ConnectionProfile::Pg(sealed));
            }
        }
        _ => {}
    }
}

/// Initializes a SQL Server database with admin rights: creates the database if missing,
/// then applies the schema (tables, the `remotino_user` role, and its grants). `admin` is a
/// transient sysadmin/dbcreator credential (Windows integrated or a SQL admin login) that is
/// used only for this call and never stored. Runs on its own thread so the sync SqlRepo
/// runtime can't clash with Tauri's.
#[tauri::command]
fn initialize_database(admin: profile::SqlProfile) -> Result<(), String> {
    let config = admin.to_config();
    std::thread::spawn(move || -> Result<(), String> {
        remotino_sql::ensure_database(&config).map_err(|e| e.to_string())?;
        remotino_sql::SqlRepo::connect_and_migrate(&config)
            .map(|_| ())
            .map_err(|e| e.to_string())
    })
    .join()
    .map_err(|_| "database initialization panicked".to_owned())?
}

/// Drops and recreates the shared database with admin rights: closes our own session first
/// (so it isn't holding the database open), drops it, then recreates the schema. **Erases
/// everything** in the shared repository. `admin` is a transient sysadmin credential.
///
/// Dropping the database also removes the current login's database user, so - if we are
/// unlocked and connect with our own provisioned `remotino_*` login - we re-provision that
/// login into the fresh database and re-seal its password to our identity. That way the user
/// keeps their identity, gets a clean database, and can unlock straight back in without
/// re-doing setup. The `sa`/integrated admin path is untouched (never re-provisioned).
#[tauri::command]
fn reset_database(admin: profile::SqlProfile, state: State<'_, AppState>) -> Result<(), String> {
    let profile_path = state.profile_path.lock().map_err(lockerr)?.clone();
    let current = profile_path.as_deref().map(profile::load);

    // The login to re-provision (our own remotino_* login only - never `sa` or a shared
    // admin), paired with our identity to re-seal to. `None` if locked, integrated, or not a
    // provisioned login.
    let relogin = match (&current, state.identity.lock().map_err(lockerr)?.as_ref()) {
        (Some(profile::ConnectionProfile::Sql(sql)), Some(identity)) => sql
            .username
            .as_deref()
            .filter(|u| u.starts_with("remotino_"))
            .map(|u| (u.to_owned(), identity.public().clone())),
        _ => None,
    };

    // Drop our own connection so ROLLBACK IMMEDIATE doesn't have to fight it.
    if let Ok(mut g) = state.session.lock() {
        *g = None;
    }

    let config = admin.to_config();
    let new_sealed = std::thread::spawn(move || -> Result<Option<String>, String> {
        remotino_sql::drop_database(&config).map_err(|e| e.to_string())?;
        remotino_sql::ensure_database(&config).map_err(|e| e.to_string())?;
        let mut repo =
            remotino_sql::SqlRepo::connect_and_migrate(&config).map_err(|e| e.to_string())?;
        match relogin {
            Some((login, recipient)) => {
                let p = remotino_sql::provision::provision_login(&mut repo, &login, &recipient)
                    .map_err(|e| e.to_string())?;
                Ok(Some(hex::encode(p.sealed_password)))
            }
            None => Ok(None),
        }
    })
    .join()
    .map_err(|_| "database reset panicked".to_owned())??;

    // Persist the fresh sealed password so our existing login works in the new database.
    if let (Some(sealed), Some(path), Some(profile::ConnectionProfile::Sql(mut sql))) =
        (new_sealed, profile_path, current)
    {
        sql.password = None;
        sql.password_sealed = Some(sealed);
        let _ = profile::save(&path, &profile::ConnectionProfile::Sql(sql));
    }

    // Re-open the session on the fresh database so the user stays signed in (no re-unlock).
    // Only possible while unlocked; a reset from the lock screen leaves it closed.
    let id_guard = state.identity.lock().map_err(lockerr)?;
    if let Some(identity) = id_guard.as_ref() {
        let mut session = open_session_for(&state, identity)?;
        self_enroll(&state, &mut session, identity);
        *state.session.lock().map_err(lockerr)? = Some(session);
    }
    Ok(())
}

/// Warns if the current shared login can modify or delete audit rows (a superuser/sysadmin,
/// or one with UPDATE/DELETE), which defeats append-only. Dispatches to whichever backend is
/// configured. Returns a message to show, or `None` when least-privilege (or local).
#[tauri::command]
fn check_sql_privileges(state: State<'_, AppState>) -> Result<Option<String>, String> {
    enum Check {
        Sql(remotino_sql::SqlConfig),
        Pg(remotino_pg::PgConfig),
    }
    let check = {
        let profile = current_profile(&state);
        let id_guard = state.identity.lock().map_err(lockerr)?;
        let identity = id_guard.as_ref().ok_or("locked")?;
        match profile {
            profile::ConnectionProfile::Sql(sql) => Check::Sql(sql.to_config_for(identity)?),
            profile::ConnectionProfile::Pg(pg) => Check::Pg(pg.to_config_for(identity)?),
            profile::ConnectionProfile::Local => return Ok(None),
        }
    };
    let over = std::thread::spawn(move || -> Result<bool, String> {
        match check {
            Check::Sql(config) => Ok(remotino_sql::check_privileges(&config)
                .map_err(|e| e.to_string())?
                .over_privileged()),
            Check::Pg(config) => remotino_pg::PgRepo::connect_checked(&config)
                .map_err(|e| e.to_string())?
                .over_privileged()
                .map_err(|e| e.to_string()),
        }
    })
    .join()
    .map_err(|_| "privilege check panicked".to_owned())??;
    if !over {
        return Ok(None);
    }
    Ok(Some(
        "This login can rewrite or erase the audit log (it's a superuser/sysadmin, or has \
         UPDATE/DELETE on the audit table), so Remotino's tamper-evident append-only guarantee \
         does not hold. Provision a least-privilege login under “Set up / add users”, and \
         connect with that instead."
            .to_owned(),
    ))
}

/// Resolves the recipient public identity for a provisioning grant: an enrolled user's key id,
/// or `None` for yourself. Locks are released before return.
fn resolve_recipient(
    state: &State<'_, AppState>,
    grantee: Option<String>,
) -> Result<PublicIdentity, String> {
    let id_guard = state.identity.lock().map_err(lockerr)?;
    let identity = id_guard.as_ref().ok_or("locked")?;
    match grantee {
        Some(kid) => {
            let key = parse_key_id(&kid)?;
            let sess_guard = state.session.lock().map_err(lockerr)?;
            let session = sess_guard.as_ref().ok_or("locked")?;
            session
                .enrolled_users()?
                .into_iter()
                .find(|u| u.identity.key_id() == key)
                .ok_or_else(|| "that user is not enrolled".to_owned())
                .map(|u| u.identity)
        }
        None => Ok(identity.public().clone()),
    }
}

/// A provisioned SQL login: the login name and its password sealed to the recipient's
/// identity (hex of a `WrappedKey` under `CONTEXT_SQL_PASSWORD` - the same shape 6c stores).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProvisionedDto {
    login: String,
    sealed_hex: String,
}

/// Creates a least-privilege SQL login (SELECT/INSERT via the `remotino_user` role) with a
/// random strong password sealed to the recipient's identity, using transient admin
/// credentials. `grantee` is an enrolled user's key id, or `None` to provision for yourself.
/// The plaintext password never leaves the SQL crate; only the sealed form is returned.
#[tauri::command]
fn provision_login(
    admin: profile::SqlProfile,
    login: String,
    grantee: Option<String>,
    state: State<'_, AppState>,
) -> Result<ProvisionedDto, String> {
    // Resolve the recipient's public identity under the locks, then release them before the
    // blocking SQL work.
    let recipient: PublicIdentity = {
        let id_guard = state.identity.lock().map_err(lockerr)?;
        let identity = id_guard.as_ref().ok_or("locked")?;
        match grantee {
            Some(kid) => {
                let key = parse_key_id(&kid)?;
                let sess_guard = state.session.lock().map_err(lockerr)?;
                let session = sess_guard.as_ref().ok_or("locked")?;
                session
                    .enrolled_users()?
                    .into_iter()
                    .find(|u| u.identity.key_id() == key)
                    .ok_or("that user is not enrolled")?
                    .identity
            }
            None => identity.public().clone(),
        }
    };
    let config = admin.to_config();
    let login_for_thread = login.clone();
    let sealed = std::thread::spawn(move || -> Result<Vec<u8>, String> {
        let mut repo =
            remotino_sql::SqlRepo::connect_and_migrate(&config).map_err(|e| e.to_string())?;
        let provisioned =
            remotino_sql::provision::provision_login(&mut repo, &login_for_thread, &recipient)
                .map_err(|e| e.to_string())?;
        Ok(provisioned.sealed_password)
    })
    .join()
    .map_err(|_| "provisioning panicked".to_owned())??;
    Ok(ProvisionedDto { login, sealed_hex: hex::encode(sealed) })
}

/// Saves a SQL profile that authenticates with a provisioned login: the password is already
/// sealed to this identity (`sealed_hex`), so it is stored as-is rather than re-sealed. Used
/// both when you provision your own login and when a user imports a setup code from an admin.
#[tauri::command]
fn import_provisioned_login(
    mut sql: profile::SqlProfile,
    sealed_hex: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let path = state
        .profile_path
        .lock()
        .map_err(lockerr)?
        .clone()
        .ok_or("app data dir unavailable")?;
    if sql.username.as_deref().unwrap_or("").trim().is_empty() {
        return Err("the setup code has no login name".to_owned());
    }
    sql.auth = profile::SqlAuthMode::Sql;
    sql.password = None;
    sql.password_sealed = Some(sealed_hex);
    crate::profile::save(&path, &profile::ConnectionProfile::Sql(sql))
}

// ---- Postgres backend admin commands (mirror the SQL Server ones) ----

/// Initializes a Postgres database with admin rights: creates it if missing, then applies the
/// schema (tables, the `remotino_user` role, grants, and the append-only trigger). `admin` is
/// a transient superuser credential used only for this call and never stored.
#[tauri::command]
fn pg_initialize_database(admin: profile::PgProfile) -> Result<(), String> {
    let config = admin.to_config();
    std::thread::spawn(move || -> Result<(), String> {
        remotino_pg::ensure_database(&config).map_err(|e| e.to_string())?;
        remotino_pg::PgRepo::connect_and_migrate(&config)
            .map(|_| ())
            .map_err(|e| e.to_string())
    })
    .join()
    .map_err(|_| "database initialization panicked".to_owned())?
}

/// Creates a least-privilege Postgres login (SELECT/INSERT via `remotino_user`) with a random
/// password sealed to the recipient. `grantee` is an enrolled user's key id, or `None` for you.
#[tauri::command]
fn pg_provision_login(
    admin: profile::PgProfile,
    login: String,
    grantee: Option<String>,
    state: State<'_, AppState>,
) -> Result<ProvisionedDto, String> {
    let recipient = resolve_recipient(&state, grantee)?;
    let database = admin.database.clone();
    let config = admin.to_config();
    let login_for_thread = login.clone();
    let sealed = std::thread::spawn(move || -> Result<Vec<u8>, String> {
        let repo = remotino_pg::PgRepo::connect_and_migrate(&config).map_err(|e| e.to_string())?;
        let provisioned = remotino_pg::provision_login(&repo, &login_for_thread, &database, &recipient)
            .map_err(|e| e.to_string())?;
        Ok(provisioned.sealed_password)
    })
    .join()
    .map_err(|_| "provisioning panicked".to_owned())??;
    Ok(ProvisionedDto { login, sealed_hex: hex::encode(sealed) })
}

/// Saves a Postgres profile authenticating with an already-sealed provisioned login (a setup
/// code, or your own provisioned login).
#[tauri::command]
fn pg_import_provisioned_login(
    mut pg: profile::PgProfile,
    sealed_hex: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let path = state
        .profile_path
        .lock()
        .map_err(lockerr)?
        .clone()
        .ok_or("app data dir unavailable")?;
    if pg.username.as_deref().unwrap_or("").trim().is_empty() {
        return Err("the setup code has no login name".to_owned());
    }
    pg.password = None;
    pg.password_sealed = Some(sealed_hex);
    crate::profile::save(&path, &profile::ConnectionProfile::Pg(pg))
}

/// Drops and recreates the shared Postgres database, re-provisioning our own `remotino_*`
/// login into the fresh one and re-opening the session (mirrors `reset_database`). Destructive.
#[tauri::command]
fn pg_reset_database(admin: profile::PgProfile, state: State<'_, AppState>) -> Result<(), String> {
    let profile_path = state.profile_path.lock().map_err(lockerr)?.clone();
    let current = profile_path.as_deref().map(profile::load);

    let relogin = match (&current, state.identity.lock().map_err(lockerr)?.as_ref()) {
        (Some(profile::ConnectionProfile::Pg(pg)), Some(identity)) => pg
            .username
            .as_deref()
            .filter(|u| u.starts_with("remotino_"))
            .map(|u| (u.to_owned(), identity.public().clone())),
        _ => None,
    };

    if let Ok(mut g) = state.session.lock() {
        *g = None;
    }

    let database = admin.database.clone();
    let config = admin.to_config();
    let new_sealed = std::thread::spawn(move || -> Result<Option<String>, String> {
        remotino_pg::drop_database(&config).map_err(|e| e.to_string())?;
        remotino_pg::ensure_database(&config).map_err(|e| e.to_string())?;
        let repo = remotino_pg::PgRepo::connect_and_migrate(&config).map_err(|e| e.to_string())?;
        match relogin {
            Some((login, recipient)) => {
                let p = remotino_pg::provision_login(&repo, &login, &database, &recipient)
                    .map_err(|e| e.to_string())?;
                Ok(Some(hex::encode(p.sealed_password)))
            }
            None => Ok(None),
        }
    })
    .join()
    .map_err(|_| "database reset panicked".to_owned())??;

    if let (Some(sealed), Some(path), Some(profile::ConnectionProfile::Pg(mut pg))) =
        (new_sealed, profile_path, current)
    {
        pg.password = None;
        pg.password_sealed = Some(sealed);
        let _ = profile::save(&path, &profile::ConnectionProfile::Pg(pg));
    }

    let id_guard = state.identity.lock().map_err(lockerr)?;
    if let Some(identity) = id_guard.as_ref() {
        let mut session = open_session_for(&state, identity)?;
        self_enroll(&state, &mut session, identity);
        *state.session.lock().map_err(lockerr)? = Some(session);
    }
    Ok(())
}

/// A server certificate's identity, shown to the user in the trust prompt.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CertInfoDto {
    /// SHA-256 fingerprint, uppercase colon-grouped hex - the form to compare visually.
    fingerprint: String,
    /// Raw SHA-256 as lowercase hex (no colons) - stored in the profile once approved.
    sha256_hex: String,
    subject: String,
    issuer: String,
    not_before: String,
    not_after: String,
}

/// Connects to a Postgres server just far enough to read its TLS certificate, and returns the
/// certificate's fingerprint and details for the user to approve. Pins nothing; carries no data
/// connection. The frontend shows the fingerprint, and on approval stores `sha256Hex` as the
/// profile's pinned fingerprint (trust-on-first-use).
#[tauri::command]
fn pg_probe_certificate(mut pg: profile::PgProfile) -> Result<CertInfoDto, String> {
    // A probe is meaningless without TLS; force it on regardless of the form's checkbox.
    pg.require_tls = true;
    let config = pg.to_config();
    let info = std::thread::spawn(move || remotino_pg::probe_certificate(&config))
        .join()
        .map_err(|_| "certificate probe panicked".to_owned())?
        .map_err(|e| e.to_string())?;
    Ok(CertInfoDto {
        fingerprint: info.fingerprint,
        sha256_hex: hex::encode(info.sha256),
        subject: info.subject,
        issuer: info.issuer,
        not_before: info.not_before,
        not_after: info.not_after,
    })
}

/// How much a local→shared migration copied.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MigrationDto {
    folders: usize,
    connections: usize,
    credentials: usize,
}

/// Copies the local single-seat store's contents into the freshly-configured shared backend
/// as new events (folders, connections, vault credentials re-created and re-sealed).
///
/// Call it after the shared profile has been saved but **before** locking to switch: the live
/// session is still the local store (the source), while the just-saved profile opens the
/// shared target. Refuses if the shared store already holds entries, so it can't duplicate.
#[tauri::command]
fn migrate_local_into_shared(state: State<'_, AppState>) -> Result<MigrationDto, String> {
    if matches!(current_profile(&state), profile::ConnectionProfile::Local) {
        return Err("switch to a shared backend before migrating".to_owned());
    }
    let id_guard = state.identity.lock().map_err(lockerr)?;
    let identity = id_guard.as_ref().ok_or("locked")?;
    let sess_guard = state.session.lock().map_err(lockerr)?;
    let source = sess_guard.as_ref().ok_or("no active session")?;
    let mut target = open_session_for(&state, identity)?;
    let summary = target.migrate_from(identity, source)?;
    Ok(MigrationDto {
        folders: summary.folders,
        connections: summary.connections,
        credentials: summary.credentials,
    })
}

/// Loads the connection tree from the store: events folded and projected through the
/// unlocked identity.
#[tauri::command]
fn load_tree(state: State<'_, AppState>) -> Result<TreeDto, String> {
    let id_guard = state.identity.lock().map_err(lockerr)?;
    let identity = id_guard.as_ref().ok_or("locked")?;
    let sess_guard = state.session.lock().map_err(lockerr)?;
    let session = sess_guard.as_ref().ok_or("locked")?;

    let events = session.events()?;
    let structure = Structure::fold(&events).map_err(stringify)?;
    let projection = Projection::project(&structure, identity).map_err(stringify)?;
    Ok(project_to_dto(&structure, &projection, &identity.key_id()))
}

/// Creates a folder and returns the reloaded tree.
#[tauri::command]
fn create_folder(
    name: String,
    parent: Option<String>,
    state: State<'_, AppState>,
) -> Result<TreeDto, String> {
    let id_guard = state.identity.lock().map_err(lockerr)?;
    let identity = id_guard.as_ref().ok_or("locked")?;
    let mut sess_guard = state.session.lock().map_err(lockerr)?;
    let session = sess_guard.as_mut().ok_or("locked")?;

    let parent = parent.map(|p| parse_folder_id(&p)).transpose()?;
    session.create_folder(identity, parent, &name)?;
    reload(session, identity)
}

/// Creates a connection in a folder and returns the reloaded tree.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn create_connection(
    folder: String,
    kind: String,
    name: String,
    host: String,
    port: u16,
    state: State<'_, AppState>,
) -> Result<TreeDto, String> {
    let id_guard = state.identity.lock().map_err(lockerr)?;
    let identity = id_guard.as_ref().ok_or("locked")?;
    let mut sess_guard = state.session.lock().map_err(lockerr)?;
    let session = sess_guard.as_mut().ok_or("locked")?;

    let folder = parse_folder_id(&folder)?;
    let conn = Connection {
        kind: match kind.as_str() {
            "rdp" => ConnectionKind::Rdp,
            _ => ConnectionKind::Ssh,
        },
        name,
        host,
        port,
        credential_ref: None,
    };
    session.create_connection(identity, folder, &conn)?;
    reload(session, identity)
}

/// Deletes a connection.
#[tauri::command]
fn delete_entry(id: String, state: State<'_, AppState>) -> Result<TreeDto, String> {
    with_session(&state, |session, identity| {
        session.delete_entry(identity, parse_entry_id(&id)?)
    })
}

/// Deletes a folder and everything under it.
#[tauri::command]
fn delete_folder(id: String, state: State<'_, AppState>) -> Result<TreeDto, String> {
    with_session(&state, |session, identity| {
        session.delete_folder(identity, parse_folder_id(&id)?)
    })
}

/// Renames a connection.
#[tauri::command]
fn rename_entry(id: String, name: String, state: State<'_, AppState>) -> Result<TreeDto, String> {
    with_session(&state, |session, identity| {
        session.rename_entry(identity, parse_entry_id(&id)?, &name)
    })
}

/// Renames a folder.
#[tauri::command]
fn rename_folder(id: String, name: String, state: State<'_, AppState>) -> Result<TreeDto, String> {
    with_session(&state, |session, identity| {
        session.rename_folder(identity, parse_folder_id(&id)?, &name)
    })
}

/// Moves a connection to another folder.
#[tauri::command]
fn move_entry(id: String, folder: String, state: State<'_, AppState>) -> Result<TreeDto, String> {
    with_session(&state, |session, identity| {
        session.move_entry(identity, parse_entry_id(&id)?, parse_folder_id(&folder)?)
    })
}

/// Moves a folder under a new parent (empty string = root).
#[tauri::command]
fn move_folder(id: String, parent: Option<String>, state: State<'_, AppState>) -> Result<TreeDto, String> {
    with_session(&state, |session, identity| {
        let parent = match parent.as_deref() {
            Some("") | None => None,
            Some(p) => Some(parse_folder_id(p)?),
        };
        session.move_folder(identity, parse_folder_id(&id)?, parent)
    })
}

/// Updates a connection's name, protocol, host and port.
#[tauri::command]
fn update_connection(
    id: String,
    name: String,
    kind: String,
    host: String,
    port: u16,
    state: State<'_, AppState>,
) -> Result<TreeDto, String> {
    with_session(&state, |session, identity| {
        session.update_entry(identity, parse_entry_id(&id)?, &name, parse_kind(&kind), &host, port)
    })
}

/// Links a connection to a vault credential (empty/None clears it).
#[tauri::command]
fn set_connection_credential(
    id: String,
    credential: Option<String>,
    state: State<'_, AppState>,
) -> Result<TreeDto, String> {
    with_session(&state, |session, identity| {
        let cred = credential
            .filter(|s| !s.is_empty())
            .map(|s| parse_credential_id(&s))
            .transpose()?;
        session.set_entry_credential(identity, parse_entry_id(&id)?, cred)
    })
}

// ---- audit log ----

/// One audit-log row as the UI sees it.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditDto {
    seq: u64,
    timestamp: String,
    /// Resolved actor: "You", an enrolled user's name, or "Unknown user".
    actor: String,
    actor_fingerprint: String,
    /// The raw action kind, e.g. `AclGranted`.
    action: String,
    /// A plain-English description of the action.
    summary: String,
}

/// The audit log plus its tamper-evidence verdict.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditLogDto {
    entries: Vec<AuditDto>,
    count: usize,
    /// Whether the hash chain is unbroken.
    intact: bool,
    /// Sequence number where it first breaks, if it does.
    broken_at: Option<u64>,
}

/// A plain-English label for a chain action kind.
fn humanize_action(action: &str) -> &'static str {
    match action {
        "FolderCreated" => "Created a folder",
        "FolderRenamed" => "Renamed a folder",
        "FolderDeleted" => "Deleted a folder",
        "FolderMoved" => "Moved a folder",
        "EntryUpserted" => "Added or edited a connection",
        "EntryDeleted" => "Deleted a connection",
        "AclGranted" => "Granted folder access",
        "AclRevoked" => "Revoked folder access",
        "VaultKeyWrapped" => "Set up a vault",
        "CredentialUpserted" => "Added or edited a credential",
        "CredentialDeleted" => "Deleted a credential",
        "CredentialGranted" => "Shared a credential",
        "CredentialRevoked" => "Revoked a credential",
        "UserEnrolled" => "Enrolled a user",
        _ => "Changed the repository",
    }
}

/// The audit log: who did what, when, newest first, with a tamper-evidence check. Any
/// unlocked user can read it - it is cleartext metadata, no content is decrypted.
#[tauri::command]
fn audit_log(state: State<'_, AppState>) -> Result<AuditLogDto, String> {
    with_session_ret(&state, |session, me| {
        let report = session.audit()?;
        let enrolled = session.enrolled_users()?;
        let my_id = me.key_id();
        let entries: Vec<AuditDto> = report
            .records
            .into_iter()
            .rev() // newest first
            .map(|r| {
                let actor = if r.actor == my_id {
                    "You".to_owned()
                } else {
                    enrolled
                        .iter()
                        .find(|u| u.identity.key_id() == r.actor)
                        .map(|u| u.name.clone())
                        .unwrap_or_else(|| "Unknown user".to_owned())
                };
                AuditDto {
                    seq: r.seq,
                    timestamp: r.timestamp,
                    actor,
                    actor_fingerprint: fingerprint_of(r.actor),
                    summary: humanize_action(&r.action).to_owned(),
                    action: r.action,
                }
            })
            .collect();
        Ok(AuditLogDto {
            count: entries.len(),
            intact: report.intact,
            broken_at: report.broken_at,
            entries,
        })
    })
}

// ---- multi-user: enrolment and folder sharing ----

/// This identity's public identity, hex-encoded, to share so others can enrol you.
#[tauri::command]
fn my_public_identity(state: State<'_, AppState>) -> Result<String, String> {
    let guard = state.identity.lock().map_err(lockerr)?;
    let id = guard.as_ref().ok_or("locked")?;
    let mut buf = Vec::new();
    ciborium::into_writer(id.public(), &mut buf).map_err(|e| e.to_string())?;
    Ok(hex::encode(buf))
}

fn users_dto(session: &Session, me: &KeyId) -> Result<Vec<UserDto>, String> {
    Ok(session
        .enrolled_users()?
        .into_iter()
        .map(|u| UserDto {
            key_id: key_id_hex(u.identity.key_id()),
            name: u.name,
            is_self: u.identity.key_id() == *me,
            fingerprint: fingerprint_of(u.identity.key_id()),
        })
        .collect())
}

/// Every enrolled user.
#[tauri::command]
fn list_users(state: State<'_, AppState>) -> Result<Vec<UserDto>, String> {
    with_session_ret(&state, |session, me| users_dto(session, &me.key_id()))
}

/// This machine's chosen display name (published when self-enrolling). Empty if not set.
#[tauri::command]
fn my_name(state: State<'_, AppState>) -> String {
    read_display_name(&state).unwrap_or_default()
}

/// Sets this machine's display name and publishes the identity under it, so other users can
/// grant folders and credentials back to it. Returns the updated user list.
#[tauri::command]
fn set_my_name(name: String, state: State<'_, AppState>) -> Result<Vec<UserDto>, String> {
    let name = name.trim().to_owned();
    if let Some(path) = state.name_path.lock().map_err(lockerr)?.clone() {
        std::fs::write(&path, &name).map_err(|e| e.to_string())?;
    }
    with_session_ret(&state, |session, me| {
        if !name.is_empty() {
            session.enroll_user(me, name.clone(), me.public().clone())?;
        }
        users_dto(session, &me.key_id())
    })
}

/// The locally-stored display name, trimmed.
fn read_display_name(state: &State<'_, AppState>) -> Option<String> {
    let path = state.name_path.lock().ok().and_then(|p| p.clone())?;
    let name = std::fs::read_to_string(path).ok()?.trim().to_owned();
    (!name.is_empty()).then_some(name)
}

/// Publishes this identity into the shared user directory under its display name, so others
/// can grant it access. On the shared SQL backend a name is derived automatically when none
/// is set (from the login, e.g. `remotino_alice` -> "alice", else a short fingerprint), so a
/// user is always discoverable without a manual "publish" step - which is what makes
/// bidirectional sharing work out of the box. No-op if already enrolled under the same name,
/// and never publishes on the single-seat local backend (there is no one else to see it).
fn self_enroll(state: &State<'_, AppState>, session: &mut Session, identity: &Identity) {
    let name = match read_display_name(state) {
        Some(n) => n,
        None => match derive_display_name(state, identity) {
            Some(derived) => {
                // Persist it so it shows in Users (editable) and republishes consistently.
                if let Some(path) = state.name_path.lock().ok().and_then(|p| p.clone()) {
                    let _ = std::fs::write(&path, &derived);
                }
                derived
            }
            None => return, // local backend, or no way to derive a name
        },
    };
    if name.is_empty() {
        return;
    }
    let already = session
        .enrolled_users()
        .map(|users| {
            users
                .iter()
                .any(|u| u.identity.key_id() == identity.key_id() && u.name == name)
        })
        .unwrap_or(false);
    if already {
        return;
    }
    let _ = session.enroll_user(identity, name, identity.public().clone());
}

/// A default display name for a shared backend: the login with any `remotino_` prefix
/// stripped, else a short fingerprint tag. `None` on the local backend (single seat).
fn derive_display_name(state: &State<'_, AppState>, identity: &Identity) -> Option<String> {
    let username = match current_profile(state) {
        profile::ConnectionProfile::Sql(sql) => sql.username,
        profile::ConnectionProfile::Pg(pg) => pg.username,
        profile::ConnectionProfile::Local => return None,
    };
    let from_login = username.as_deref().and_then(|u| {
        let base = u.strip_prefix("remotino_").unwrap_or(u).trim();
        (!base.is_empty()).then(|| base.to_owned())
    });
    Some(from_login.unwrap_or_else(|| {
        let hex = key_id_hex(identity.key_id());
        format!("user-{}", hex.get(..8).unwrap_or(&hex))
    }))
}

/// Enrolls a user from their hex-encoded public identity. Returns the updated list.
#[tauri::command]
fn enroll_user(
    name: String,
    identity: String,
    state: State<'_, AppState>,
) -> Result<Vec<UserDto>, String> {
    let bytes = hex::decode(identity.trim()).map_err(|_| "invalid identity string".to_owned())?;
    let public: PublicIdentity =
        ciborium::from_reader(bytes.as_slice()).map_err(|_| "unreadable identity".to_owned())?;
    with_session_ret(&state, |session, me| {
        session.enroll_user(me, name, public)?;
        users_dto(session, &me.key_id())
    })
}

/// Key ids currently granted read access to a folder.
#[tauri::command]
fn folder_grantees(folder: String, state: State<'_, AppState>) -> Result<Vec<String>, String> {
    let fid = parse_folder_id(&folder)?;
    with_session_ret(&state, |session, _| {
        Ok(session.folder_grantees(fid)?.into_iter().map(key_id_hex).collect())
    })
}

/// Grants a user access to a folder; returns the folder's updated grantees.
#[tauri::command]
fn grant_folder(
    folder: String,
    grantee: String,
    state: State<'_, AppState>,
) -> Result<Vec<String>, String> {
    let fid = parse_folder_id(&folder)?;
    let key = parse_key_id(&grantee)?;
    with_session_ret(&state, |session, me| {
        session.grant_folder(me, fid, key)?;
        Ok(session.folder_grantees(fid)?.into_iter().map(key_id_hex).collect())
    })
}

/// Revokes a user's access to a folder; returns the folder's updated grantees.
#[tauri::command]
fn revoke_folder(
    folder: String,
    grantee: String,
    state: State<'_, AppState>,
) -> Result<Vec<String>, String> {
    let fid = parse_folder_id(&folder)?;
    let key = parse_key_id(&grantee)?;
    with_session_ret(&state, |session, me| {
        session.revoke_folder(me, fid, key)?;
        Ok(session.folder_grantees(fid)?.into_iter().map(key_id_hex).collect())
    })
}

/// Key ids currently granted access to a credential.
#[tauri::command]
fn credential_grantees(credential: String, state: State<'_, AppState>) -> Result<Vec<String>, String> {
    let cid = parse_credential_id(&credential)?;
    with_session_ret(&state, |session, _| {
        Ok(session.credential_grantees(cid)?.into_iter().map(key_id_hex).collect())
    })
}

/// Shares a credential with an enrolled user; returns the credential's updated grantees.
#[tauri::command]
fn grant_credential(
    credential: String,
    grantee: String,
    state: State<'_, AppState>,
) -> Result<Vec<String>, String> {
    let cid = parse_credential_id(&credential)?;
    let key = parse_key_id(&grantee)?;
    with_session_ret(&state, |session, me| {
        session.grant_credential(me, cid, key)?;
        Ok(session.credential_grantees(cid)?.into_iter().map(key_id_hex).collect())
    })
}

/// Revokes a user's access to a credential; returns the credential's updated grantees.
#[tauri::command]
fn revoke_credential(
    credential: String,
    grantee: String,
    state: State<'_, AppState>,
) -> Result<Vec<String>, String> {
    let cid = parse_credential_id(&credential)?;
    let key = parse_key_id(&grantee)?;
    with_session_ret(&state, |session, me| {
        session.revoke_credential(me, cid, key)?;
        Ok(session.credential_grantees(cid)?.into_iter().map(key_id_hex).collect())
    })
}

// ---- personal vault ----

/// Creates a vault credential. `auth` is "password" or "key"; `secret` is the password or
/// the OpenSSH private key text. For a key, its public fingerprint is computed here.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn create_credential(
    name: String,
    kind: String,
    username: String,
    domain: Option<String>,
    auth: String,
    secret: String,
    passphrase: Option<String>,
    state: State<'_, AppState>,
) -> Result<TreeDto, String> {
    let secret = build_secret(&auth, secret, passphrase)?;
    let kind = parse_kind(&kind);
    with_session(&state, move |session, identity| {
        let cred = Credential {
            name,
            kind,
            username,
            domain: domain.filter(|d| !d.is_empty()),
            secret,
        };
        session.create_credential(identity, &cred).map(|_| ())
    })
}

/// Updates a vault credential. A non-empty `secret` replaces it; otherwise the existing
/// secret is kept.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn update_credential(
    id: String,
    name: String,
    kind: String,
    username: String,
    domain: Option<String>,
    auth: String,
    secret: Option<String>,
    passphrase: Option<String>,
    state: State<'_, AppState>,
) -> Result<TreeDto, String> {
    let new_secret = match secret.filter(|s| !s.is_empty()) {
        Some(s) => Some(build_secret(&auth, s, passphrase)?),
        None => None,
    };
    let kind = parse_kind(&kind);
    with_session(&state, move |session, identity| {
        session.update_credential(
            identity,
            parse_credential_id(&id)?,
            name,
            kind,
            username,
            domain.filter(|d| !d.is_empty()),
            new_secret,
        )
    })
}

/// Renames a vault credential.
#[tauri::command]
fn rename_credential(id: String, name: String, state: State<'_, AppState>) -> Result<TreeDto, String> {
    with_session(&state, |session, identity| {
        session.rename_credential(identity, parse_credential_id(&id)?, &name)
    })
}

/// Deletes a vault credential.
#[tauri::command]
fn delete_credential(id: String, state: State<'_, AppState>) -> Result<TreeDto, String> {
    with_session(&state, |session, identity| {
        session.delete_credential(identity, parse_credential_id(&id)?)
    })
}

fn parse_kind(kind: &str) -> ConnectionKind {
    match kind {
        "rdp" => ConnectionKind::Rdp,
        _ => ConnectionKind::Ssh,
    }
}

fn build_secret(
    auth: &str,
    secret: String,
    passphrase: Option<String>,
) -> Result<CredentialSecret, String> {
    match auth {
        "key" => {
            let fingerprint = ssh_fingerprint(&secret)?;
            Ok(CredentialSecret::Key {
                private_key: secret,
                passphrase: passphrase.filter(|p| !p.is_empty()),
                fingerprint,
            })
        }
        _ => Ok(CredentialSecret::Password { password: secret }),
    }
}

/// The SHA256 public-key fingerprint of an OpenSSH private key, e.g. `SHA256:…`.
fn ssh_fingerprint(private_key: &str) -> Result<String, String> {
    use russh::keys::ssh_key::{HashAlg, PrivateKey};
    let key = PrivateKey::from_openssh(private_key)
        .map_err(|_| "not a valid OpenSSH private key".to_owned())?;
    Ok(key.public_key().fingerprint(HashAlg::Sha256).to_string())
}

// ---- live SSH sessions ----

/// Opens an SSH session for a terminal tab. The UI supplies `id` (its tab id) so events
/// and later `ssh_send`/`ssh_resize`/`ssh_close` calls can be routed back to this session.
///
/// The password is used only for this call and never stored.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn ssh_connect(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    id: String,
    host: String,
    port: u16,
    cols: u32,
    rows: u32,
    entry_id: Option<String>,
    username: Option<String>,
    password: Option<String>,
) -> Result<(), String> {
    // Resolve the credential (if the connection is linked to one) before any await, so no
    // lock is held across it. Falls back to the manually-typed username/password.
    let auth = build_ssh_auth(&state, entry_id.as_deref(), username, password)?;
    let sessions = state.ssh.clone();
    ssh::connect(app, sessions, id, host, port, auth, cols, rows).await
}

/// Builds SSH auth from a linked vault credential, or the manually-typed fallback.
fn build_ssh_auth(
    state: &State<'_, AppState>,
    entry_id: Option<&str>,
    username: Option<String>,
    password: Option<String>,
) -> Result<ssh::Auth, String> {
    if let Some(eid) = entry_id {
        if let Some(cred) = resolve_credential(state, eid)? {
            let Credential { username, secret, .. } = cred;
            let auth = match secret {
                CredentialSecret::Password { password } => ssh::Auth::Password { username, password },
                CredentialSecret::Key { private_key, passphrase, .. } => ssh::Auth::Key {
                    username,
                    private_key,
                    passphrase,
                },
                _ => return Err("unsupported credential type".to_owned()),
            };
            return Ok(auth);
        }
    }
    Ok(ssh::Auth::Password {
        username: username.unwrap_or_default(),
        password: password.unwrap_or_default(),
    })
}

/// Resolves the decrypted credential a connection is linked to. Locks are released before
/// return - the plaintext is used only within the connect commands, never sent to the UI.
fn resolve_credential(
    state: &State<'_, AppState>,
    entry_id: &str,
) -> Result<Option<Credential>, String> {
    let id_guard = state.identity.lock().map_err(lockerr)?;
    let identity = id_guard.as_ref().ok_or("locked")?;
    let sess_guard = state.session.lock().map_err(lockerr)?;
    let session = sess_guard.as_ref().ok_or("locked")?;
    session.entry_credential(identity, parse_entry_id(entry_id)?)
}

/// Writes user keystrokes to a live SSH session.
#[tauri::command]
fn ssh_send(state: State<'_, AppState>, id: String, bytes: Vec<u8>) {
    ssh::send(&state.ssh, &id, bytes);
}

/// Tells a live SSH session its terminal was resized.
#[tauri::command]
fn ssh_resize(state: State<'_, AppState>, id: String, cols: u32, rows: u32) {
    ssh::resize(&state.ssh, &id, cols, rows);
}

/// Closes a live SSH session.
#[tauri::command]
fn ssh_close(state: State<'_, AppState>, id: String) {
    ssh::close(&state.ssh, &id);
}

// ---- live RDP sessions (sidecar) ----

/// Opens an RDP session by spawning the sidecar. `on_event` is a channel that receives raw
/// framebuffer/status messages. Password used only for this call, never stored.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn rdp_connect(
    state: State<'_, AppState>,
    id: String,
    host: String,
    port: u16,
    width: u16,
    height: u16,
    on_event: tauri::ipc::Channel<tauri::ipc::InvokeResponseBody>,
    entry_id: Option<String>,
    username: Option<String>,
    password: Option<String>,
    domain: Option<String>,
) -> Result<(), String> {
    // Prefer a linked credential; otherwise use the manually-typed values.
    let (username, password, domain) = match entry_id.as_deref() {
        Some(eid) => match resolve_credential(&state, eid)? {
            Some(cred) => match cred.secret {
                CredentialSecret::Password { password } => (cred.username, password, cred.domain),
                _ => return Err("RDP does not use key credentials".to_owned()),
            },
            None => (username.unwrap_or_default(), password.unwrap_or_default(), domain),
        },
        None => (username.unwrap_or_default(), password.unwrap_or_default(), domain),
    };
    // TOFU: the pin we already hold for this host (if any) + where to record a first-use one.
    let kh_path = state.known_hosts_path.lock().map_err(lockerr)?.clone();
    let expected = kh_path.as_deref().and_then(|p| known_hosts::get(p, &host));

    let sessions = state.rdp.clone();
    rdp::connect(
        sessions, id, host, port, username, password, domain, width, height, expected, kh_path,
        on_event,
    )
    .await
}

/// Drops the pinned server key for a host, so the next RDP connect trusts on first use.
#[tauri::command]
fn forget_host_key(host: String, state: State<'_, AppState>) -> Result<(), String> {
    if let Some(p) = state.known_hosts_path.lock().map_err(lockerr)?.clone() {
        known_hosts::forget(&p, &host);
    }
    Ok(())
}

/// Forwards a JSON input event to a live RDP session.
#[tauri::command]
fn rdp_input(state: State<'_, AppState>, id: String, event: serde_json::Value) {
    if let Ok(json) = serde_json::to_string(&event) {
        rdp::input(&state.rdp, &id, json);
    }
}

/// Closes a live RDP session.
#[tauri::command]
fn rdp_close(state: State<'_, AppState>, id: String) {
    rdp::close(&state.rdp, &id);
}

// ---- helpers ----

fn reload(session: &Session, identity: &Identity) -> Result<TreeDto, String> {
    let events = session.events()?;
    let structure = Structure::fold(&events).map_err(stringify)?;
    let projection = Projection::project(&structure, identity).map_err(stringify)?;
    Ok(project_to_dto(&structure, &projection, &identity.key_id()))
}

/// Runs a mutating session op under the identity+session locks, then returns the fresh tree.
fn with_session<F>(state: &State<'_, AppState>, op: F) -> Result<TreeDto, String>
where
    F: FnOnce(&mut Session, &Identity) -> Result<(), String>,
{
    let id_guard = state.identity.lock().map_err(lockerr)?;
    let identity = id_guard.as_ref().ok_or("locked")?;
    let mut sess_guard = state.session.lock().map_err(lockerr)?;
    let session = sess_guard.as_mut().ok_or("locked")?;
    op(session, identity)?;
    reload(session, identity)
}

/// Like [`with_session`] but returns whatever the op produces (for user/sharing queries).
fn with_session_ret<T, F>(state: &State<'_, AppState>, op: F) -> Result<T, String>
where
    F: FnOnce(&mut Session, &Identity) -> Result<T, String>,
{
    let id_guard = state.identity.lock().map_err(lockerr)?;
    let identity = id_guard.as_ref().ok_or("locked")?;
    let mut sess_guard = state.session.lock().map_err(lockerr)?;
    let session = sess_guard.as_mut().ok_or("locked")?;
    op(session, identity)
}

fn parse_key_id(s: &str) -> Result<KeyId, String> {
    let bytes = hex::decode(s).map_err(|_| "invalid key id".to_owned())?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "key id wrong length".to_owned())?;
    Ok(KeyId(Digest(arr)))
}

/// Full 32-byte key id as hex - the canonical form for grant/revoke round-trips. (KeyId's
/// Display is a short 8-byte prefix, only for human-readable fingerprints.)
fn key_id_hex(k: KeyId) -> String {
    hex::encode(k.0 .0)
}

fn project_to_dto(structure: &Structure, projection: &Projection, me: &KeyId) -> TreeDto {
    // A folder/credential is "shared" when a grant exists for someone other than me. The
    // owner always holds a self-grant, so this is exactly "granted to at least one other".
    let folder_shared = |id: &FolderId| {
        structure
            .grants
            .get(id)
            .is_some_and(|g| g.keys().any(|k| k != me))
    };
    let credential_shared = |id: &CredentialId| {
        structure
            .credential_grants
            .get(id)
            .is_some_and(|g| g.keys().any(|k| k != me))
    };

    let folders = projection
        .folders
        .iter()
        .map(|(id, f)| FolderDto {
            id: id.to_string(),
            parent: f.parent.map(|p| p.to_string()),
            name: f.name.clone(),
            readable: f.readable,
            shared: folder_shared(id),
        })
        .collect();

    // The projection drops the folder association; recover it from the structure.
    let connections = projection
        .connections
        .iter()
        .filter_map(|(id, c)| {
            let folder = structure.entries.get(id)?.folder;
            Some(ConnectionDto {
                id: id.to_string(),
                folder: folder.to_string(),
                kind: match c.kind {
                    ConnectionKind::Rdp => "rdp",
                    _ => "ssh",
                }
                .to_owned(),
                name: c.name.clone(),
                host: c.host.clone(),
                port: c.port,
                credential: c.credential_ref.clone(),
                shared: folder_shared(&folder),
            })
        })
        .collect();

    let credentials = projection
        .credentials
        .iter()
        .map(|(id, c)| {
            let (is_key, fingerprint) = match &c.secret {
                CredentialSecret::Key { fingerprint, .. } => (true, Some(fingerprint.clone())),
                _ => (false, None),
            };
            CredentialDto {
                id: id.to_string(),
                name: c.name.clone(),
                kind: match c.kind {
                    ConnectionKind::Rdp => "rdp",
                    _ => "ssh",
                }
                .to_owned(),
                username: c.username.clone(),
                domain: c.domain.clone(),
                is_key,
                fingerprint,
                shared: credential_shared(id),
            }
        })
        .collect();

    TreeDto { folders, connections, credentials }
}

fn parse_folder_id(s: &str) -> Result<FolderId, String> {
    let bytes = hex::decode(s).map_err(|_| "invalid folder id".to_owned())?;
    let arr: [u8; ID_LEN] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "folder id wrong length".to_owned())?;
    Ok(FolderId(arr))
}

fn parse_entry_id(s: &str) -> Result<EntryId, String> {
    let bytes = hex::decode(s).map_err(|_| "invalid entry id".to_owned())?;
    let arr: [u8; ID_LEN] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "entry id wrong length".to_owned())?;
    Ok(EntryId(arr))
}

fn parse_credential_id(s: &str) -> Result<CredentialId, String> {
    let bytes = hex::decode(s).map_err(|_| "invalid credential id".to_owned())?;
    let arr: [u8; ID_LEN] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "credential id wrong length".to_owned())?;
    Ok(CredentialId(arr))
}

fn fingerprint(identity: &Identity) -> String {
    fingerprint_of(identity.key_id())
}

fn fingerprint_of(key_id: KeyId) -> String {
    let hex = key_id.to_string();
    hex.as_bytes()
        .chunks(4)
        .filter_map(|c| core::str::from_utf8(c).ok())
        .collect::<Vec<_>>()
        .join(" ")
}

fn identity_file(state: &State<'_, AppState>) -> Result<PathBuf, String> {
    state
        .identity_path
        .lock()
        .map_err(lockerr)?
        .clone()
        .ok_or_else(|| "app data dir unavailable".to_owned())
}

/// The saved connection profile (defaults to Local).
fn current_profile(state: &State<'_, AppState>) -> profile::ConnectionProfile {
    state
        .profile_path
        .lock()
        .ok()
        .and_then(|p| p.clone())
        .map(|p| profile::load(&p))
        .unwrap_or_default()
}

/// Opens a session on whichever backend the profile selects.
fn open_session_for(
    state: &State<'_, AppState>,
    identity: &Identity,
) -> Result<Session, String> {
    match current_profile(state) {
        profile::ConnectionProfile::Local => Session::open(&store_file(state)?, identity),
        // Regular unlock only checks the schema (connect_checked): a per-user login has just
        // SELECT/INSERT, not the DDL rights connect_and_migrate needs. The schema is created
        // once by an admin via "Test & initialize". The login password is unsealed with the
        // identity here (6c).
        profile::ConnectionProfile::Sql(sql) => {
            Session::open_sql(&sql.to_config_for(identity)?, identity, false)
        }
        // Postgres, same as SQL Server: connect_checked with the identity-unsealed password.
        profile::ConnectionProfile::Pg(pg) => {
            Session::open_pg(&pg.to_config_for(identity)?, identity, false)
        }
    }
}

fn store_file(state: &State<'_, AppState>) -> Result<PathBuf, String> {
    state
        .store_path
        .lock()
        .map_err(lockerr)?
        .clone()
        .ok_or_else(|| "app data dir unavailable".to_owned())
}

fn stringify<E: core::fmt::Display>(e: E) -> String {
    e.to_string()
}
fn lockerr<E>(_: E) -> String {
    "internal lock poisoned".to_owned()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(AppState::new())
        .setup(|app| {
            let dir = app.path().app_data_dir()?;
            let state = app.state::<AppState>();
            if let Ok(mut p) = state.identity_path.lock() {
                *p = Some(dir.join("identity.cbor"));
            }
            if let Ok(mut p) = state.store_path.lock() {
                *p = Some(dir.join("store.db"));
            }
            if let Ok(mut p) = state.known_hosts_path.lock() {
                *p = Some(dir.join("known_hosts.json"));
            }
            if let Ok(mut p) = state.profile_path.lock() {
                *p = Some(dir.join("connection.json"));
            }
            if let Ok(mut p) = state.name_path.lock() {
                *p = Some(dir.join("display_name.txt"));
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            identity_status,
            create_identity,
            unlock,
            lock,
            reset_app,
            get_connection_profile,
            set_connection_profile,
            initialize_database,
            reset_database,
            check_sql_privileges,
            provision_login,
            import_provisioned_login,
            pg_initialize_database,
            pg_provision_login,
            pg_import_provisioned_login,
            pg_reset_database,
            pg_probe_certificate,
            migrate_local_into_shared,
            load_tree,
            create_folder,
            create_connection,
            delete_entry,
            delete_folder,
            rename_entry,
            rename_folder,
            move_entry,
            move_folder,
            update_connection,
            set_connection_credential,
            my_public_identity,
            list_users,
            my_name,
            set_my_name,
            audit_log,
            enroll_user,
            folder_grantees,
            grant_folder,
            revoke_folder,
            credential_grantees,
            grant_credential,
            revoke_credential,
            create_credential,
            update_credential,
            rename_credential,
            delete_credential,
            ssh_connect,
            ssh_send,
            ssh_resize,
            ssh_close,
            rdp_connect,
            rdp_input,
            rdp_close,
            forget_host_key
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
