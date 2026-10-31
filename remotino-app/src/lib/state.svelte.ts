// App-wide reactive state, Svelte 5 runes.
//
// Deliberately thin: this holds UI state (theme, which screen, open session tabs, palette
// visibility). The *data* - the connection tree - comes from the backend projection and
// lives in `tree.svelte.ts`. Keeping them apart mirrors the backend split between the
// structural fold and the decrypted projection.

import type { Connection } from "./tree.svelte";
import { stashSsh } from "./sshpending";

export type Theme = "dark" | "light";
export type Screen = "unlock" | "app";

/** A remote session shown as a tab. */
export interface SessionTab {
  id: string;
  name: string;
  kind: "rdp" | "ssh";
  status: "connecting" | "connected" | "error";
  /** Host, carried for the session surface (e.g. the terminal title bar). */
  host?: string;
}

class UiState {
  theme = $state<Theme>("dark");
  screen = $state<Screen>("unlock");

  /** Open session tabs. Tab 0 (Connections) is implicit and always present, never here. */
  sessions = $state<SessionTab[]>([]);
  /** Index into [Connections, ...sessions]. 0 is the connection tree. */
  activeTab = $state(0);

  paletteOpen = $state(false);

  /** A security warning about the current backend (e.g. an over-privileged SQL login), or
   *  null. Shown as a dismissible banner in the shell. */
  sqlWarning = $state<string | null>(null);

  /** The connection awaiting an SSH auth prompt, or null. Drives the SshAuth modal. */
  connectTarget = $state<Connection | null>(null);

  toggleTheme() {
    this.theme = this.theme === "dark" ? "light" : "dark";
  }

  /** Route a connection to its surface. If it has a linked vault credential, connect
   *  straight away (the backend resolves the secret); otherwise prompt for credentials. */
  requestConnect(c: Connection) {
    if (c.credential) {
      const id = crypto.randomUUID();
      // Auto-fill: hand the connection's entry id to the surface, no secret in the webview.
      stashSsh(id, { host: c.host, port: c.port, entryId: c.id });
      this.openSession({ id, name: c.name, kind: c.kind, status: "connecting", host: c.host });
    } else {
      this.connectTarget = c;
    }
  }

  /** Update a live tab's status (connecting -> connected/error). */
  setStatus(id: string, status: SessionTab["status"]) {
    const s = this.sessions.find((t) => t.id === id);
    if (s) s.status = status;
  }

  unlock() {
    this.screen = "app";
  }

  openSession(tab: SessionTab) {
    // Focus an existing tab for the same target rather than stacking duplicates.
    const existing = this.sessions.findIndex((s) => s.id === tab.id);
    if (existing >= 0) {
      this.activeTab = existing + 1;
      return;
    }
    this.sessions.push(tab);
    this.activeTab = this.sessions.length; // last tab (0 is Connections)
    this.paletteOpen = false;
  }

  closeSession(id: string) {
    const i = this.sessions.findIndex((s) => s.id === id);
    if (i < 0) return;
    this.sessions.splice(i, 1);
    // Keep the active tab valid: clamp into the new range.
    if (this.activeTab > this.sessions.length) {
      this.activeTab = this.sessions.length;
    }
  }
}

export const ui = new UiState();

/** Transient in-memory admin sign-in for DB setup, so provisioning several users in a row
 *  doesn't re-prompt. Never persisted; cleared when the process restarts. */
class AdminCreds {
  auth = $state<"integrated" | "sql">("integrated");
  user = $state("sa");
  pass = $state("");
}
export const adminCreds = new AdminCreds();
