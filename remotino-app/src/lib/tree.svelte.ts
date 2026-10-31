// The connection tree the user sees.
//
// Shaped to match `remotino_model::projection::Projection`: folders that may be readable
// (with a name) or opaque (Restricted - visible but not decryptable), and connections that
// only appear inside folders the user can read. Right now this is sample data; wiring it to
// a Tauri command that returns the real projection is a drop-in replacement, because the
// shape is identical.

export interface Folder {
  id: string;
  parent: string | null;
  /** Decrypted name, or null when the folder is Restricted (no grant). */
  name: string | null;
  readable: boolean;
  /** Granted to at least one other user. */
  shared?: boolean;
}

export interface Connection {
  id: string;
  folder: string;
  kind: "rdp" | "ssh";
  name: string;
  host: string;
  port: number;
  /** Id of the vault credential this connection uses, if any. */
  credential?: string | null;
  /** Whether this connection's folder is shared with another user. */
  shared?: boolean;
}

/** A vault credential as the UI sees it — metadata only, never the secret itself. */
export interface Credential {
  id: string;
  name: string;
  kind: "rdp" | "ssh";
  username: string;
  domain: string | null;
  isKey: boolean;
  fingerprint: string | null;
  /** Granted to at least one other user. */
  shared?: boolean;
}

export interface TreeData {
  folders: Folder[];
  connections: Connection[];
  credentials: Credential[];
}

/** Sample projection: a realistic mix, including one Restricted folder. */
export const sample: TreeData = {
  folders: [
    { id: "f-prod", parent: null, name: "Production", readable: true, shared: true },
    { id: "f-db", parent: "f-prod", name: "Databases", readable: true },
    { id: "f-web", parent: "f-prod", name: "Web tier", readable: true },
    { id: "f-infra", parent: null, name: "Infrastructure", readable: true },
    { id: "f-net", parent: "f-infra", name: "Network", readable: true },
    { id: "f-lab", parent: null, name: "Lab", readable: true },
    // Restricted: exists in the graph, but this user holds no key for it.
    { id: "f-fin", parent: null, name: null, readable: false },
  ],
  connections: [
    { id: "c1", folder: "f-db", kind: "ssh", name: "db-prod-01", host: "db-prod-01.use1.internal", port: 22 },
    { id: "c2", folder: "f-db", kind: "ssh", name: "db-prod-02", host: "db-prod-02.use1.internal", port: 22 },
    { id: "c3", folder: "f-db", kind: "rdp", name: "db-admin-jump", host: "10.20.4.11", port: 3389 },
    { id: "c4", folder: "f-web", kind: "ssh", name: "web-lb-01", host: "web-lb-01.use1.internal", port: 22 },
    { id: "c5", folder: "f-web", kind: "ssh", name: "web-app-01", host: "web-app-01.use1.internal", port: 22 },
    { id: "c6", folder: "f-web", kind: "ssh", name: "web-app-02", host: "web-app-02.use1.internal", port: 22 },
    { id: "c7", folder: "f-net", kind: "ssh", name: "core-sw-01", host: "10.0.0.2", port: 22 },
    { id: "c8", folder: "f-net", kind: "rdp", name: "fw-mgmt", host: "10.0.0.1", port: 3389 },
    { id: "c9", folder: "f-infra", kind: "rdp", name: "dc-01", host: "10.0.1.10", port: 3389 },
    { id: "c10", folder: "f-infra", kind: "rdp", name: "dc-02", host: "10.0.1.11", port: 3389 },
    { id: "c11", folder: "f-lab", kind: "rdp", name: "win11-test", host: "192.0.2.202", port: 3389 },
    { id: "c12", folder: "f-lab", kind: "ssh", name: "pi-hole", host: "198.51.100.53", port: 22 },
  ],
  credentials: [
    { id: "k1", name: "prod-admin", kind: "rdp", username: "administrator", domain: "CORP", isKey: false, fingerprint: null, shared: true },
    { id: "k2", name: "linux-root", kind: "ssh", username: "root", domain: null, isKey: false, fingerprint: null },
    { id: "k3", name: "deploy key", kind: "ssh", username: "deploy", domain: null, isKey: true, fingerprint: "SHA256:7Xm9Qp2kLz8vAe3Rtn0bYc1JdWf6HgUq4Ns5MxPoi" },
  ],
};

class TreeState {
  data = $state<TreeData>(sample);
  /** Collapsed folder ids. */
  collapsed = $state<Set<string>>(new Set());
  /** Current filter text. */
  filter = $state("");
  /** Selected node id (folder or connection). */
  selected = $state<string | null>(null);

  toggle(id: string) {
    const next = new Set(this.collapsed);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    this.collapsed = next;
  }

  /** All connections flattened, for the command palette. */
  get allConnections(): Connection[] {
    return this.data.connections;
  }

  /** Folder name lookup, for palette path display. */
  folderName(id: string): string {
    return this.data.folders.find((f) => f.id === id)?.name ?? "?";
  }
}

export const tree = new TreeState();
