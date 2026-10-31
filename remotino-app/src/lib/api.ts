// The bridge to the Rust backend.
//
// Every call goes through invoke() when running inside Tauri. When running in a plain
// browser (the vite-dev preview, where there is no Tauri IPC), it falls back to sample
// data so the UI still renders for design work. The fallback is clearly gated on
// `isTauri` - it is a dev convenience, never a code path that ships pretending to be real.

import { invoke, Channel } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { sample, type TreeData } from "./tree.svelte";

/** True only inside the Tauri webview, where invoke() reaches Rust. */
export const isTauri =
  typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

export interface IdentityInfo {
  fingerprint: string;
}

export interface IdentityStatus {
  exists: boolean;
  fingerprint: string | null;
}

const SAMPLE_FP = "a3f1 9c22 7b04 e8d5";

export async function identityStatus(): Promise<IdentityStatus> {
  // Returning user with a known public-key fingerprint, in browser preview.
  if (!isTauri) return { exists: true, fingerprint: SAMPLE_FP };
  return invoke<IdentityStatus>("identity_status");
}

export async function createIdentity(passphrase: string): Promise<IdentityInfo> {
  if (!isTauri) return { fingerprint: SAMPLE_FP };
  return invoke<IdentityInfo>("create_identity", { passphrase });
}

export async function unlock(passphrase: string): Promise<IdentityInfo> {
  if (!isTauri) return { fingerprint: SAMPLE_FP };
  return invoke<IdentityInfo>("unlock", { passphrase });
}

export async function lock(): Promise<void> {
  if (!isTauri) return;
  await invoke("lock");
}

/** Wipes this machine's identity, local store, and settings, then restarts to first run. */
export async function resetApp(): Promise<void> {
  if (!isTauri) return;
  await invoke("reset_app");
}

// ---- connection profile (backend selection) ----

export interface SqlProfile {
  host: string;
  port: number;
  instance: string | null;
  database: string;
  trustCert: boolean;
  auth: "integrated" | "sql";
  username: string | null;
  /** Cleartext password to seal (only sent when the user types a new one). */
  password: string | null;
  /** Present when a password is already sealed to the identity; never editable directly. */
  passwordSealed?: string | null;
}

export interface PgProfile {
  host: string;
  port: number;
  database: string;
  username: string | null;
  /** Cleartext password to seal (only sent when the user types a new one). */
  password: string | null;
  /** Present when a password is already sealed to the identity; never editable directly. */
  passwordSealed?: string | null;
  /** Require TLS. When false the connection is plaintext (loopback / throwaway only). */
  requireTls?: boolean;
  /** The trusted server-certificate fingerprint (SHA-256 hex), pinned on first use. */
  pinnedFingerprint?: string | null;
}

/** A server TLS certificate's identity, shown to the user before they pin it. */
export interface CertInfo {
  /** SHA-256 fingerprint, uppercase colon-grouped hex — compare this visually. */
  fingerprint: string;
  /** Raw SHA-256 as lowercase hex; what gets stored as the pinned fingerprint. */
  sha256Hex: string;
  subject: string;
  issuer: string;
  notBefore: string;
  notAfter: string;
}

/** Reads a Postgres server's TLS certificate (pins nothing) so the user can approve it. */
export async function pgProbeCertificate(pg: PgProfile): Promise<CertInfo> {
  if (!isTauri) throw new Error("Postgres is only available in the desktop app.");
  return invoke<CertInfo>("pg_probe_certificate", { pg });
}

export type ConnectionProfile =
  | { backend: "local" }
  | ({ backend: "sql" } & SqlProfile)
  | ({ backend: "pg" } & PgProfile);

export async function getConnectionProfile(): Promise<ConnectionProfile> {
  if (!isTauri) return { backend: "local" };
  return invoke<ConnectionProfile>("get_connection_profile");
}

export async function setConnectionProfile(profile: ConnectionProfile): Promise<void> {
  if (!isTauri) return;
  await invoke("set_connection_profile", { profile });
}

/** Initializes the database with admin rights: creates it if missing, applies the schema. */
export async function initializeDatabase(admin: SqlProfile): Promise<void> {
  if (!isTauri) throw new Error("SQL Server is only available in the desktop app.");
  await invoke("initialize_database", { admin });
}

/** Drops and recreates the shared database (erases everything), with admin rights. */
export async function resetDatabase(admin: SqlProfile): Promise<void> {
  if (!isTauri) throw new Error("SQL Server is only available in the desktop app.");
  await invoke("reset_database", { admin });
}

/**
 * Warns if the current SQL login can modify/delete audit rows (defeating append-only).
 * Returns a message to display, or null when the login is correctly least-privilege.
 */
export async function checkSqlPrivileges(): Promise<string | null> {
  if (!isTauri) return null;
  return invoke<string | null>("check_sql_privileges");
}

/** A provisioned login: name + password sealed to the recipient's identity. */
export interface Provisioned {
  login: string;
  sealedHex: string;
}

/**
 * Provisions a least-privilege SQL login with a random password sealed to the recipient.
 * `grantee` is an enrolled user's keyId, or null to provision for yourself.
 */
export async function provisionLogin(
  admin: SqlProfile,
  login: string,
  grantee: string | null,
): Promise<Provisioned> {
  if (!isTauri) throw new Error("SQL Server is only available in the desktop app.");
  return invoke<Provisioned>("provision_login", { admin, login, grantee });
}

/** Saves a SQL profile that authenticates with an already-sealed provisioned password. */
export async function importProvisionedLogin(sql: SqlProfile, sealedHex: string): Promise<void> {
  if (!isTauri) throw new Error("SQL Server is only available in the desktop app.");
  await invoke("import_provisioned_login", { sql, sealedHex });
}

// ---- Postgres backend admin ----

/** Initializes the Postgres database with superuser rights: creates it if missing, applies schema. */
export async function pgInitializeDatabase(admin: PgProfile): Promise<void> {
  if (!isTauri) throw new Error("Postgres is only available in the desktop app.");
  await invoke("pg_initialize_database", { admin });
}

/** Drops and recreates the shared Postgres database (erases everything), with superuser rights. */
export async function pgResetDatabase(admin: PgProfile): Promise<void> {
  if (!isTauri) throw new Error("Postgres is only available in the desktop app.");
  await invoke("pg_reset_database", { admin });
}

/**
 * Provisions a least-privilege Postgres login with a random password sealed to the recipient.
 * `grantee` is an enrolled user's keyId, or null to provision for yourself.
 */
export async function pgProvisionLogin(
  admin: PgProfile,
  login: string,
  grantee: string | null,
): Promise<Provisioned> {
  if (!isTauri) throw new Error("Postgres is only available in the desktop app.");
  return invoke<Provisioned>("pg_provision_login", { admin, login, grantee });
}

/** Saves a Postgres profile that authenticates with an already-sealed provisioned password. */
export async function pgImportProvisionedLogin(pg: PgProfile, sealedHex: string): Promise<void> {
  if (!isTauri) throw new Error("Postgres is only available in the desktop app.");
  await invoke("pg_import_provisioned_login", { pg, sealedHex });
}

/**
 * A self-contained "setup code": everything a provisioned user needs to connect, in one
 * string. The sealed password inside only opens for the recipient's identity, so the code is
 * safe to send over any channel.
 */
export interface SetupCode {
  /** Which backend this code configures. Absent means "sql" (older codes). */
  backend?: "sql" | "pg";
  host: string;
  port: number;
  /** SQL Server only. */
  instance?: string | null;
  database: string;
  /** SQL Server only. */
  trustCert?: boolean;
  /** Postgres only: require TLS on the connection. */
  requireTls?: boolean;
  /** Postgres only: the trusted server-certificate fingerprint (SHA-256 hex). */
  pinnedFingerprint?: string | null;
  login: string;
  sealedHex: string;
}

export function encodeSetupCode(c: SetupCode): string {
  return btoa(JSON.stringify(c));
}

export function decodeSetupCode(s: string): SetupCode {
  let o: SetupCode;
  try {
    o = JSON.parse(atob(s.trim()));
  } catch {
    throw new Error("That doesn't look like a valid setup code.");
  }
  if (!o.login || !o.sealedHex || !o.host || !o.database) {
    throw new Error("That setup code is missing required fields.");
  }
  if (!o.backend) o.backend = "sql";
  return o;
}

// ---- multi-user: enrolment and folder sharing ----

export interface User {
  keyId: string;
  name: string;
  fingerprint: string;
  /** True for your own enrolled identity. */
  isSelf?: boolean;
}

/** This machine's published display name, or "" if not set yet. */
export async function myName(): Promise<string> {
  if (!isTauri) return "";
  return invoke<string>("my_name");
}

/** Sets your display name and publishes your identity so others can grant access to you. */
export async function setMyName(name: string): Promise<User[]> {
  if (!isTauri) return [];
  return invoke<User[]>("set_my_name", { name });
}

/** This identity's public identity (hex), to share so others can enrol you. */
export async function myPublicIdentity(): Promise<string> {
  if (!isTauri) return "preview-identity-string";
  return invoke<string>("my_public_identity");
}

export async function listUsers(): Promise<User[]> {
  if (!isTauri) return [];
  return invoke<User[]>("list_users");
}

export async function enrollUser(name: string, identity: string): Promise<User[]> {
  if (!isTauri) return [];
  return invoke<User[]>("enroll_user", { name, identity });
}

export async function folderGrantees(folder: string): Promise<string[]> {
  if (!isTauri) return [];
  return invoke<string[]>("folder_grantees", { folder });
}

export async function grantFolder(folder: string, grantee: string): Promise<string[]> {
  if (!isTauri) return [];
  return invoke<string[]>("grant_folder", { folder, grantee });
}

export async function revokeFolder(folder: string, grantee: string): Promise<string[]> {
  if (!isTauri) return [];
  return invoke<string[]>("revoke_folder", { folder, grantee });
}

// ---- audit log ----

export interface AuditEntry {
  seq: number;
  timestamp: string;
  actor: string;
  actorFingerprint: string;
  action: string;
  summary: string;
}

export interface AuditLog {
  entries: AuditEntry[];
  count: number;
  intact: boolean;
  brokenAt: number | null;
}

/** The audit log: who did what, when, newest first, with a tamper-evidence check. */
export async function auditLog(): Promise<AuditLog> {
  if (!isTauri) {
    const now = Date.now();
    const mk = (seq: number, mins: number, actor: string, action: string, summary: string): AuditEntry => ({
      seq,
      timestamp: new Date(now - mins * 60000).toISOString(),
      actor,
      actorFingerprint: actor === "You" ? "a3f1 9c22 7b04 e8d5" : "be22 04c1 77af 9d31",
      action,
      summary,
    });
    const entries = [
      mk(11, 2, "You", "CredentialGranted", "Shared a credential"),
      mk(10, 5, "You", "AclGranted", "Granted folder access"),
      mk(9, 9, "Alice", "EntryUpserted", "Added or edited a connection"),
      mk(8, 40, "Alice", "UserEnrolled", "Enrolled a user"),
      mk(7, 62, "You", "CredentialUpserted", "Added or edited a credential"),
      mk(6, 130, "You", "FolderCreated", "Created a folder"),
    ];
    return { entries, count: entries.length, intact: true, brokenAt: null };
  }
  return invoke<AuditLog>("audit_log");
}

export async function credentialGrantees(credential: string): Promise<string[]> {
  if (!isTauri) return [];
  return invoke<string[]>("credential_grantees", { credential });
}

export async function grantCredential(credential: string, grantee: string): Promise<string[]> {
  if (!isTauri) return [];
  return invoke<string[]>("grant_credential", { credential, grantee });
}

export async function revokeCredential(credential: string, grantee: string): Promise<string[]> {
  if (!isTauri) return [];
  return invoke<string[]>("revoke_credential", { credential, grantee });
}

export async function loadTree(): Promise<TreeData> {
  if (!isTauri) return sample;
  return invoke<TreeData>("load_tree");
}

/** Counts of what a local→shared migration copied. */
export interface MigrationResult {
  folders: number;
  connections: number;
  credentials: number;
}

/**
 * Copies the local single-seat store's folders, connections and vault credentials into the
 * freshly-configured shared backend as new events. Call after saving the shared profile but
 * before locking to switch. Throws if the shared store already has entries.
 */
export async function migrateLocalIntoShared(): Promise<MigrationResult> {
  if (!isTauri) throw new Error("Migration is only available in the desktop app.");
  return invoke<MigrationResult>("migrate_local_into_shared");
}

/** A new connection's fields. Kind, name, host, port; folder is where it lands. */
export interface NewConnection {
  folder: string;
  kind: "rdp" | "ssh";
  name: string;
  host: string;
  port: number;
}

export async function createConnection(c: NewConnection): Promise<TreeData> {
  if (!isTauri) {
    // Browser preview: append locally so the design still exercises the flow.
    const id = `c-${Math.random().toString(36).slice(2, 8)}`;
    sample.connections.push({ id, ...c });
    return { folders: sample.folders, connections: sample.connections, credentials: sample.credentials };
  }
  return invoke<TreeData>("create_connection", {
    folder: c.folder,
    kind: c.kind,
    name: c.name,
    host: c.host,
    port: c.port,
  });
}

export async function createFolder(
  name: string,
  parent: string | null,
): Promise<TreeData> {
  if (!isTauri) {
    const id = `f-${Math.random().toString(36).slice(2, 8)}`;
    sample.folders.push({ id, parent, name, readable: true });
    return { folders: sample.folders, connections: sample.connections, credentials: sample.credentials };
  }
  return invoke<TreeData>("create_folder", { name, parent });
}

// ---- edit operations: delete / rename / move ----

function browserMutate(fn: () => void): TreeData {
  fn();
  return {
    folders: sample.folders,
    connections: sample.connections,
    credentials: sample.credentials,
  };
}

export async function deleteEntry(id: string): Promise<TreeData> {
  if (!isTauri)
    return browserMutate(() => {
      sample.connections = sample.connections.filter((c) => c.id !== id);
    });
  return invoke<TreeData>("delete_entry", { id });
}

export async function deleteFolder(id: string): Promise<TreeData> {
  if (!isTauri)
    return browserMutate(() => {
      // Cascade: drop the folder, its descendants, and their connections.
      const doomed = new Set([id]);
      let grew = true;
      while (grew) {
        grew = false;
        for (const f of sample.folders) {
          if (f.parent && doomed.has(f.parent) && !doomed.has(f.id)) {
            doomed.add(f.id);
            grew = true;
          }
        }
      }
      sample.folders = sample.folders.filter((f) => !doomed.has(f.id));
      sample.connections = sample.connections.filter((c) => !doomed.has(c.folder));
    });
  return invoke<TreeData>("delete_folder", { id });
}

export async function updateConnection(
  id: string,
  c: { name: string; kind: "rdp" | "ssh"; host: string; port: number },
): Promise<TreeData> {
  if (!isTauri)
    return browserMutate(() => {
      const x = sample.connections.find((k) => k.id === id);
      if (x) {
        x.name = c.name;
        x.kind = c.kind;
        x.host = c.host;
        x.port = c.port;
      }
    });
  return invoke<TreeData>("update_connection", { id, name: c.name, kind: c.kind, host: c.host, port: c.port });
}

export async function renameEntry(id: string, name: string): Promise<TreeData> {
  if (!isTauri)
    return browserMutate(() => {
      const c = sample.connections.find((x) => x.id === id);
      if (c) c.name = name;
    });
  return invoke<TreeData>("rename_entry", { id, name });
}

export async function renameFolder(id: string, name: string): Promise<TreeData> {
  if (!isTauri)
    return browserMutate(() => {
      const f = sample.folders.find((x) => x.id === id);
      if (f) f.name = name;
    });
  return invoke<TreeData>("rename_folder", { id, name });
}

export async function moveEntry(id: string, folder: string): Promise<TreeData> {
  if (!isTauri)
    return browserMutate(() => {
      const c = sample.connections.find((x) => x.id === id);
      if (c) c.folder = folder;
    });
  return invoke<TreeData>("move_entry", { id, folder });
}

export async function moveFolder(id: string, parent: string | null): Promise<TreeData> {
  if (!isTauri)
    return browserMutate(() => {
      const f = sample.folders.find((x) => x.id === id);
      if (f) f.parent = parent;
    });
  return invoke<TreeData>("move_folder", { id, parent });
}

/** Links a connection to a vault credential, or clears it (null). */
export async function setConnectionCredential(
  id: string,
  credential: string | null,
): Promise<TreeData> {
  if (!isTauri)
    return browserMutate(() => {
      const c = sample.connections.find((x) => x.id === id);
      if (c) c.credential = credential;
    });
  return invoke<TreeData>("set_connection_credential", { id, credential });
}

// ---- vault credentials ----

export interface NewCredential {
  name: string;
  kind: "rdp" | "ssh";
  username: string;
  domain?: string | null;
  auth: "password" | "key";
  secret: string; // password or OpenSSH private key text
  passphrase?: string | null;
}

export async function createCredential(c: NewCredential): Promise<TreeData> {
  if (!isTauri)
    return browserMutate(() => {
      sample.credentials.push({
        id: `k-${Math.random().toString(36).slice(2, 8)}`,
        name: c.name,
        kind: c.kind,
        username: c.username,
        domain: c.domain || null,
        isKey: c.auth === "key",
        fingerprint: c.auth === "key" ? "SHA256:preview-only-no-parse" : null,
      });
    });
  return invoke<TreeData>("create_credential", {
    name: c.name,
    kind: c.kind,
    username: c.username,
    domain: c.domain ?? null,
    auth: c.auth,
    secret: c.secret,
    passphrase: c.passphrase ?? null,
  });
}

export interface EditCredential {
  id: string;
  name: string;
  kind: "rdp" | "ssh";
  username: string;
  domain?: string | null;
  auth: "password" | "key";
  /** Empty/omitted keeps the existing secret; set to replace it. */
  secret?: string;
  passphrase?: string | null;
}

export async function updateCredential(c: EditCredential): Promise<TreeData> {
  if (!isTauri)
    return browserMutate(() => {
      const x = sample.credentials.find((k) => k.id === c.id);
      if (x) {
        x.name = c.name;
        x.kind = c.kind;
        x.username = c.username;
        x.domain = c.domain || null;
        if (c.secret) x.isKey = c.auth === "key";
      }
    });
  return invoke<TreeData>("update_credential", {
    id: c.id,
    name: c.name,
    kind: c.kind,
    username: c.username,
    domain: c.domain ?? null,
    auth: c.auth,
    secret: c.secret ?? null,
    passphrase: c.passphrase ?? null,
  });
}

export async function renameCredential(id: string, name: string): Promise<TreeData> {
  if (!isTauri)
    return browserMutate(() => {
      const c = sample.credentials.find((x) => x.id === id);
      if (c) c.name = name;
    });
  return invoke<TreeData>("rename_credential", { id, name });
}

export async function deleteCredential(id: string): Promise<TreeData> {
  if (!isTauri)
    return browserMutate(() => {
      sample.credentials = sample.credentials.filter((c) => c.id !== id);
    });
  return invoke<TreeData>("delete_credential", { id });
}

// ---- live SSH sessions ----

export interface SshConnectArgs {
  id: string;
  host: string;
  port: number;
  cols: number;
  rows: number;
  /** Link to a connection so the backend resolves its vault credential. */
  entryId?: string;
  /** Manual auth, used when there is no linked credential. */
  username?: string;
  password?: string;
}

/** Opens an SSH session. Resolves once the shell is up, rejects with a short reason. */
export async function sshConnect(args: SshConnectArgs): Promise<void> {
  if (!isTauri) throw new Error("SSH is only available in the desktop app.");
  await invoke("ssh_connect", { ...args });
}

export async function sshSend(id: string, bytes: Uint8Array): Promise<void> {
  if (!isTauri) return;
  // Tauri serialises a number[]; the command signature is Vec<u8>.
  await invoke("ssh_send", { id, bytes: Array.from(bytes) });
}

export async function sshResize(id: string, cols: number, rows: number): Promise<void> {
  if (!isTauri) return;
  await invoke("ssh_resize", { id, cols, rows });
}

export async function sshClose(id: string): Promise<void> {
  if (!isTauri) return;
  await invoke("ssh_close", { id });
}

/** Subscribes to a session's output. Returns an unlisten fn to call on teardown. */
export async function onSshData(
  id: string,
  handler: (bytes: Uint8Array) => void,
): Promise<UnlistenFn> {
  if (!isTauri) return () => {};
  return listen<{ bytes: number[] }>(`ssh://data/${id}`, (e) => {
    handler(Uint8Array.from(e.payload.bytes));
  });
}

/** Subscribes to a session's close/EOF. Returns an unlisten fn. */
export async function onSshClosed(
  id: string,
  handler: () => void,
): Promise<UnlistenFn> {
  if (!isTauri) return () => {};
  return listen(`ssh://closed/${id}`, () => handler());
}

// ---- live RDP sessions (sidecar) ----

export interface RdpConnectArgs {
  id: string;
  host: string;
  port: number;
  width: number;
  height: number;
  /** Link to a connection so the backend resolves its vault credential. */
  entryId?: string;
  /** Manual auth, used when there is no linked credential. */
  username?: string;
  password?: string;
  domain?: string | null;
}

/** Opens an RDP session. `onEvent` receives each raw sidecar message as an ArrayBuffer:
 *  `[u8 kind][payload]` — 1 = frame, 2 = size, 3 = status. */
export async function rdpConnect(
  args: RdpConnectArgs,
  onEvent: (buf: ArrayBuffer) => void,
): Promise<void> {
  if (!isTauri) throw new Error("RDP is only available in the desktop app.");
  const ch = new Channel<ArrayBuffer>();
  ch.onmessage = (msg) => onEvent(msg);
  await invoke("rdp_connect", { ...args, onEvent: ch });
}

/** Sends an input event in the sidecar's schema, e.g. {t:"m_move",x,y}. */
export async function rdpInput(id: string, event: Record<string, unknown>): Promise<void> {
  if (!isTauri) return;
  await invoke("rdp_input", { id, event });
}

export async function rdpClose(id: string): Promise<void> {
  if (!isTauri) return;
  await invoke("rdp_close", { id });
}

/** Drops the pinned server key for a host, so the next connect trusts on first use. */
export async function forgetHostKey(host: string): Promise<void> {
  if (!isTauri) return;
  await invoke("forget_host_key", { host });
}
