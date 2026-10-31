// Transient handoff of SSH credentials from the auth prompt to the terminal that consumes
// them. Deliberately a plain module-level Map, NOT reactive UI state: the password lives
// here only between "user clicked Connect" and "Terminal mounted and called connect", and
// the Terminal deletes it on read. It never lands in `ui.sessions`, never renders, and is
// gone the moment the connection is initiated.

export interface PendingSsh {
  host: string;
  port: number;
  // Manual auth: typed username/password.
  username?: string;
  password?: string;
  // Auto-fill: the connection's entry id, so the backend resolves the linked credential
  // and the secret never enters the webview.
  entryId?: string;
}

const pending = new Map<string, PendingSsh>();

export function stashSsh(id: string, creds: PendingSsh) {
  pending.set(id, creds);
}

/** Reads and removes the credentials for a session id. Single-use by design. */
export function takeSsh(id: string): PendingSsh | undefined {
  const c = pending.get(id);
  pending.delete(id);
  return c;
}
