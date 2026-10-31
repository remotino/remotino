<script lang="ts">
  import { tree, type Connection, type Folder, type Credential, type TreeData } from "$lib/tree.svelte";
  import { ui } from "$lib/state.svelte";
  import * as api from "$lib/api";
  import CreateModal from "./CreateModal.svelte";
  import CredentialModal from "./CredentialModal.svelte";
  import ShareModal, { type ShareTarget } from "./ShareModal.svelte";

  // The folder or credential being shared (grant/revoke users), or null.
  let shareTarget = $state<ShareTarget | null>(null);

  let createOpen = $state(false);
  let credOpen = $state(false);
  // When set, the create modal opens in "edit this connection" mode.
  let editConn = $state<{ id: string; kind: "rdp" | "ssh"; name: string; host: string; port: number } | null>(null);
  // When set, the credential modal opens in "edit this credential" mode.
  let editCred = $state<{ id: string; name: string; kind: "rdp" | "ssh"; username: string; domain: string | null; isKey: boolean } | null>(null);

  // Right-click context menu, inline rename, and drag-to-move state.
  type NodeKind = "folder" | "conn" | "cred";
  type MenuTarget = { kind: NodeKind; id: string; name: string };
  let menu = $state<{ x: number; y: number; t: MenuTarget } | null>(null);
  let confirming = $state(false);
  let picking = $state(false);
  let renamingId = $state<string | null>(null);
  let renameValue = $state("");
  let drag = $state<{ kind: "folder" | "conn"; id: string } | null>(null);
  let dropFolder = $state<string | null>(null);
  let opError = $state("");

  type Row =
    | { kind: "folder"; depth: number; folder: Folder; childCount: number }
    | { kind: "conn"; depth: number; conn: Connection };

  // Flatten the folder graph into ordered rows, honouring collapse and the filter. Doing
  // this in a derived keeps rendering a straight list map - fast even at hundreds of rows,
  // which is the whole point (DESIGN.md 2: tree filter < 16ms at 1000 entries).
  const rows = $derived.by((): Row[] => {
    const q = tree.filter.trim().toLowerCase();
    const { folders, connections } = tree.data;

    // Stable, name-sorted order. The backend returns folders/connections in HashMap order,
    // which is non-deterministic and reshuffles on every reload; sorting here pins the
    // listing so only a renamed item moves (to its new alphabetical slot), not everything.
    const cmp = (an: string, bn: string, aId: string, bId: string) => {
      const a = an.toLowerCase();
      const b = bn.toLowerCase();
      if (a !== b) return a < b ? -1 : 1;
      return aId < bId ? -1 : 1; // tie-break by id, so equal names stay put
    };
    const childFolders = (parent: string | null) =>
      folders
        .filter((f) => f.parent === parent)
        .sort((a, b) => {
          // Restricted (nameless) folders sort last, stably by id.
          if (!a.name && !b.name) return a.id < b.id ? -1 : 1;
          if (!a.name) return 1;
          if (!b.name) return -1;
          return cmp(a.name, b.name, a.id, b.id);
        });
    const folderConns = (id: string) =>
      connections
        .filter((c) => c.folder === id)
        .sort((a, b) => cmp(a.name, b.name, a.id, b.id));

    const connMatches = (c: Connection) =>
      !q || c.name.toLowerCase().includes(q) || c.host.toLowerCase().includes(q);
    const folderMatches = (f: Folder) =>
      !q || (f.name?.toLowerCase().includes(q) ?? false);

    // A folder is shown if it matches, or any descendant connection matches. When
    // filtering, folders auto-expand so matches are visible without manual clicking.
    const subtreeHasMatch = (f: Folder): boolean => {
      if (folderMatches(f)) return true;
      if (folderConns(f.id).some(connMatches)) return true;
      return childFolders(f.id).some(subtreeHasMatch);
    };

    const out: Row[] = [];
    const walk = (parent: string | null, depth: number) => {
      for (const f of childFolders(parent)) {
        if (q && !subtreeHasMatch(f)) continue;
        const conns = folderConns(f.id).filter(connMatches);
        const kids = childFolders(f.id);
        out.push({ kind: "folder", depth, folder: f, childCount: conns.length });
        const collapsed = tree.collapsed.has(f.id) && !q; // filter overrides collapse
        if (!collapsed && f.readable) {
          walk(f.id, depth + 1);
          for (const c of conns) out.push({ kind: "conn", depth: depth + 1, conn: c });
        }
      }
    };
    walk(null, 0);
    return out;
  });

  function openConn(c: Connection) {
    ui.requestConnect(c);
  }

  // What folder a new connection should default into: the selected folder, or the folder
  // of the selected connection, so "add" lands where the user is looking.
  const selectedFolder = $derived.by((): string | null => {
    const sel = tree.selected;
    if (!sel) return null;
    if (tree.data.folders.some((f) => f.id === sel)) return sel;
    return tree.data.connections.find((c) => c.id === sel)?.folder ?? null;
  });

  // Run a mutating op and adopt the fresh tree it returns; surface a brief error otherwise.
  async function apply(p: Promise<TreeData>) {
    try {
      tree.data = await p;
      opError = "";
    } catch (e) {
      opError = String(e);
      setTimeout(() => (opError = ""), 3500);
    }
  }

  function openMenu(e: MouseEvent, t: MenuTarget) {
    e.preventDefault();
    menu = { x: e.clientX, y: e.clientY, t };
    confirming = false;
    picking = false;
  }
  function closeMenu() {
    menu = null;
    confirming = false;
    picking = false;
  }

  // The vault credentials that match a connection's protocol (RDP creds for RDP, etc.).
  function matchingCreds(connId: string): Credential[] {
    const conn = tree.data.connections.find((c) => c.id === connId);
    if (!conn) return [];
    return tree.data.credentials.filter((c) => c.kind === conn.kind);
  }
  function assignCred(connId: string, credId: string | null) {
    apply(api.setConnectionCredential(connId, credId));
    closeMenu();
  }
  function startEdit(connId: string) {
    const c = tree.data.connections.find((x) => x.id === connId);
    if (c) {
      editConn = { id: c.id, kind: c.kind, name: c.name, host: c.host, port: c.port };
      createOpen = true;
    }
    closeMenu();
  }
  function startEditCred(credId: string) {
    const c = tree.data.credentials.find((x) => x.id === credId);
    if (c) {
      editCred = { id: c.id, name: c.name, kind: c.kind, username: c.username, domain: c.domain, isKey: c.isKey };
      credOpen = true;
    }
    closeMenu();
  }
  // The display name of the credential a connection uses, for the row indicator.
  function credName(conn: Connection): string | null {
    if (!conn.credential) return null;
    return tree.data.credentials.find((c) => c.id === conn.credential)?.name ?? "credential";
  }

  function startRename(t: MenuTarget) {
    renamingId = t.id;
    renameValue = t.name;
    closeMenu();
  }
  function commitRename(kind: NodeKind, id: string) {
    const name = renameValue.trim();
    renamingId = null;
    if (!name) return;
    if (kind === "folder") apply(api.renameFolder(id, name));
    else if (kind === "cred") apply(api.renameCredential(id, name));
    else apply(api.renameEntry(id, name));
  }

  function doDelete(t: MenuTarget) {
    if (t.kind === "folder") apply(api.deleteFolder(t.id));
    else if (t.kind === "cred") apply(api.deleteCredential(t.id));
    else apply(api.deleteEntry(t.id));
    closeMenu();
  }

  // How a credential reads in the list: DOMAIN\user / user for passwords, a short
  // fingerprint for keys.
  function credDetail(c: Credential): string {
    if (c.isKey) return c.fingerprint ? c.fingerprint.replace(/^SHA256:/, "").slice(0, 12) + "…" : "key";
    return c.domain ? `${c.domain}\\${c.username}` : c.username;
  }

  function onDragStart(e: DragEvent, kind: "folder" | "conn", id: string) {
    drag = { kind, id };
    e.dataTransfer?.setData("text/plain", id);
    if (e.dataTransfer) e.dataTransfer.effectAllowed = "move";
  }
  function onDragEnd() {
    drag = null;
    dropFolder = null;
  }
  function onFolderDragOver(e: DragEvent, folder: Folder) {
    if (!drag || !folder.readable) return;
    if (drag.kind === "folder" && drag.id === folder.id) return; // onto itself
    e.preventDefault();
    dropFolder = folder.id;
  }
  function onFolderDrop(e: DragEvent, folder: Folder) {
    e.preventDefault();
    e.stopPropagation(); // keep the root-drop handler from also firing
    const d = drag;
    drag = null;
    dropFolder = null;
    if (!d || !folder.readable) return;
    if (d.kind === "conn") apply(api.moveEntry(d.id, folder.id));
    else if (d.id !== folder.id) apply(api.moveFolder(d.id, folder.id));
  }
  function onRootDrop() {
    const d = drag;
    drag = null;
    dropFolder = null;
    if (d && d.kind === "folder") apply(api.moveFolder(d.id, null)); // to top level
  }
</script>

<div class="pane">
  <div class="search">
    <svg class="ico" width="13" height="13" viewBox="0 0 16 16" aria-hidden="true">
      <circle cx="7" cy="7" r="4.3" fill="none" stroke="currentColor" stroke-width="1.6" />
      <path d="M10.4 10.4 14 14" stroke="currentColor" stroke-width="1.6" fill="none" />
    </svg>
    <input
      bind:value={tree.filter}
      placeholder="Filter connections…"
      spellcheck="false"
    />
    <button class="hint" onclick={() => (ui.paletteOpen = true)} title="Command palette">
      ⌘K
    </button>
    <button class="add" onclick={() => { editConn = null; createOpen = true; }} title="New connection or folder" aria-label="New">
      <svg width="14" height="14" viewBox="0 0 16 16" aria-hidden="true">
        <path d="M8 3v10M3 8h10" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" />
      </svg>
    </button>
  </div>

  <CreateModal bind:open={createOpen} preselect={selectedFolder} edit={editConn} />
  <CredentialModal bind:open={credOpen} edit={editCred} />
  <ShareModal bind:target={shareTarget} />

  <!-- Pinned personal vault, always at the top. -->
  <div class="vault">
    <div class="vault-head">
      <svg class="vault-ico" width="13" height="13" viewBox="0 0 16 16" aria-hidden="true">
        <circle cx="6" cy="7" r="3.1" fill="none" stroke="currentColor" stroke-width="1.6" />
        <path d="M8.2 8.4 13.5 13.7M11 11l1.6-1.6M12.4 12.4l1.2-1.2" stroke="currentColor" stroke-width="1.6" fill="none" stroke-linecap="round" />
      </svg>
      <span class="vault-title">Credentials</span>
      <span class="vcount">{tree.data.credentials.length || ""}</span>
      <button class="vadd" onclick={() => { editCred = null; credOpen = true; }} title="New credential" aria-label="New credential">
        <svg width="13" height="13" viewBox="0 0 16 16" aria-hidden="true">
          <path d="M8 3v10M3 8h10" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" />
        </svg>
      </button>
    </div>
    <div class="vault-list">
      {#each [...tree.data.credentials].sort((a, b) => (a.name.toLowerCase() < b.name.toLowerCase() ? -1 : 1)) as cred (cred.id)}
        {#if renamingId === cred.id}
          <div class="row cred">
            <span class="badge {cred.kind}">{cred.kind.toUpperCase()}</span>
            {#if cred.isKey}
              <svg class="keyglyph" width="12" height="12" viewBox="0 0 16 16" aria-hidden="true"><circle cx="5.5" cy="6.5" r="2.6" fill="none" stroke="currentColor" stroke-width="1.5" /><path d="M7.4 8 13 13.6M11 12l1.4-1.4" stroke="currentColor" stroke-width="1.5" fill="none" stroke-linecap="round" /></svg>
            {/if}
            <!-- svelte-ignore a11y_autofocus -->
            <input
              class="rename"
              bind:value={renameValue}
              autofocus
              onkeydown={(e) => {
                if (e.key === "Enter") commitRename("cred", cred.id);
                else if (e.key === "Escape") (renamingId = null);
              }}
              onblur={() => commitRename("cred", cred.id)}
            />
          </div>
        {:else}
          <button
            class="row cred"
            oncontextmenu={(e) => openMenu(e, { kind: "cred", id: cred.id, name: cred.name })}
          >
            <span class="badge {cred.kind}">{cred.kind.toUpperCase()}</span>
            {#if cred.isKey}
              <svg class="keyglyph" width="12" height="12" viewBox="0 0 16 16" aria-hidden="true"><circle cx="5.5" cy="6.5" r="2.6" fill="none" stroke="currentColor" stroke-width="1.5" /><path d="M7.4 8 13 13.6M11 12l1.4-1.4" stroke="currentColor" stroke-width="1.5" fill="none" stroke-linecap="round" /></svg>
            {/if}
            <span class="cname">{cred.name}</span>
            {#if cred.shared}<span class="shared-tag" title="Shared with another user">shared</span>{/if}
            <span class="host">{credDetail(cred)}</span>
          </button>
        {/if}
      {/each}
      {#if tree.data.credentials.length === 0}
        <div class="vault-empty">No credentials yet — add one with +.</div>
      {/if}
    </div>
  </div>

  <!-- Dropping a dragged folder onto empty space moves it to the top level. -->
  <div
    class="rows"
    role="tree"
    tabindex="-1"
    ondragover={(e) => {
      if (drag?.kind === "folder") e.preventDefault();
    }}
    ondrop={onRootDrop}
  >
    {#each rows as row (row.kind === "folder" ? row.folder.id : row.conn.id)}
      {#if row.kind === "folder"}
        {#if renamingId === row.folder.id}
          <div class="row folder" style="padding-left:{8 + row.depth * 15}px">
            <span class="chev open">▸</span>
            <svg class="fico" width="13" height="13" viewBox="0 0 16 16" aria-hidden="true">
              <path d="M1.5 4.2c0-.7.5-1.2 1.2-1.2h3l1.4 1.5h6.2c.7 0 1.2.5 1.2 1.2v6.4c0 .7-.5 1.2-1.2 1.2H2.7c-.7 0-1.2-.5-1.2-1.2z" fill="currentColor" opacity="0.85" />
            </svg>
            <!-- svelte-ignore a11y_autofocus -->
            <input
              class="rename"
              bind:value={renameValue}
              autofocus
              onkeydown={(e) => {
                if (e.key === "Enter") commitRename("folder", row.folder.id);
                else if (e.key === "Escape") (renamingId = null);
              }}
              onblur={() => commitRename("folder", row.folder.id)}
            />
          </div>
        {:else}
          <button
            class="row folder"
            class:sel={tree.selected === row.folder.id}
            class:drop={dropFolder === row.folder.id}
            style="padding-left:{8 + row.depth * 15}px"
            draggable={row.folder.readable}
            ondragstart={(e) => onDragStart(e, "folder", row.folder.id)}
            ondragend={onDragEnd}
            ondragover={(e) => onFolderDragOver(e, row.folder)}
            ondragleave={() => {
              if (dropFolder === row.folder.id) dropFolder = null;
            }}
            ondrop={(e) => onFolderDrop(e, row.folder)}
            oncontextmenu={(e) =>
              row.folder.readable &&
              openMenu(e, { kind: "folder", id: row.folder.id, name: row.folder.name ?? "" })}
            onclick={() => {
              tree.selected = row.folder.id;
              if (row.folder.readable) tree.toggle(row.folder.id);
            }}
          >
            {#if row.folder.readable}
              <span class="chev" class:open={!tree.collapsed.has(row.folder.id) || !!tree.filter}>▸</span>
              <svg class="fico" width="13" height="13" viewBox="0 0 16 16" aria-hidden="true">
                <path d="M1.5 4.2c0-.7.5-1.2 1.2-1.2h3l1.4 1.5h6.2c.7 0 1.2.5 1.2 1.2v6.4c0 .7-.5 1.2-1.2 1.2H2.7c-.7 0-1.2-.5-1.2-1.2z" fill="currentColor" opacity="0.85" />
              </svg>
              <span class="fname">{row.folder.name}</span>
              {#if row.folder.shared}<span class="shared-tag" title="Shared with another user">shared</span>{/if}
              <span class="count">{row.childCount || ""}</span>
            {:else}
              <!-- Restricted: visible node, no name, no expand. The whole access model. -->
              <span class="chev locked">·</span>
              <svg class="fico locked" width="12" height="12" viewBox="0 0 16 16" aria-hidden="true">
                <rect x="3.2" y="7" width="9.6" height="6.3" rx="1.2" fill="currentColor" />
                <path d="M4.9 7V5.3a3.1 3.1 0 0 1 6.2 0V7" fill="none" stroke="currentColor" stroke-width="1.5" />
              </svg>
              <span class="fname restricted">Restricted</span>
            {/if}
          </button>
        {/if}
      {:else if renamingId === row.conn.id}
        <div class="row conn" style="padding-left:{8 + row.depth * 15}px">
          <span class="badge {row.conn.kind}">{row.conn.kind.toUpperCase()}</span>
          <!-- svelte-ignore a11y_autofocus -->
          <input
            class="rename"
            bind:value={renameValue}
            autofocus
            onkeydown={(e) => {
              if (e.key === "Enter") commitRename("conn", row.conn.id);
              else if (e.key === "Escape") (renamingId = null);
            }}
            onblur={() => commitRename("conn", row.conn.id)}
          />
        </div>
      {:else}
        <button
          class="row conn"
          class:sel={tree.selected === row.conn.id}
          style="padding-left:{8 + row.depth * 15}px"
          draggable="true"
          ondragstart={(e) => onDragStart(e, "conn", row.conn.id)}
          ondragend={onDragEnd}
          oncontextmenu={(e) =>
            openMenu(e, { kind: "conn", id: row.conn.id, name: row.conn.name })}
          onclick={() => (tree.selected = row.conn.id)}
          ondblclick={() => openConn(row.conn)}
        >
          <span class="badge {row.conn.kind}">{row.conn.kind.toUpperCase()}</span>
          <span class="cname">{row.conn.name}</span>
          {#if row.conn.shared}<span class="shared-tag" title="In a folder shared with another user">shared</span>{/if}
          {#if credName(row.conn)}
            <svg class="credmark" width="11" height="11" viewBox="0 0 16 16" aria-hidden="true"><circle cx="5.5" cy="6.5" r="2.6" fill="none" stroke="currentColor" stroke-width="1.6" /><path d="M7.4 8 13 13.6M11 12l1.4-1.4" stroke="currentColor" stroke-width="1.6" fill="none" stroke-linecap="round" /></svg>
          {/if}
          <span class="host">{row.conn.host}<span class="port">:{row.conn.port}</span></span>
        </button>
      {/if}
    {/each}

    {#if rows.length === 0}
      <div class="empty">No connections match “{tree.filter}”.</div>
    {/if}
  </div>

  {#if opError}
    <div class="op-error">{opError}</div>
  {/if}
</div>

{#if menu}
  <button class="menu-overlay" onclick={closeMenu} oncontextmenu={(e) => e.preventDefault()} aria-label="Close menu"></button>
  <div class="menu" style="left:{menu.x}px; top:{menu.y}px" role="menu">
    {#if picking && menu}
      <div class="confirm">Use credential</div>
      {#each matchingCreds(menu.t.id) as c (c.id)}
        {@const active = tree.data.connections.find((x) => x.id === menu?.t.id)?.credential === c.id}
        <button role="menuitem" class:on={active} onclick={() => menu && assignCred(menu.t.id, c.id)}>
          {c.isKey ? "🔑 " : ""}{c.name}
        </button>
      {/each}
      {#if matchingCreds(menu.t.id).length === 0}
        <div class="confirm dim">No {tree.data.connections.find((x) => x.id === menu?.t.id)?.kind.toUpperCase()} credentials yet.</div>
      {/if}
      <button role="menuitem" onclick={() => menu && assignCred(menu.t.id, null)}>No credential</button>
    {:else if !confirming}
      <button role="menuitem" onclick={() => menu && startRename(menu.t)}>Rename</button>
      {#if menu.t.kind === "conn"}
        <button role="menuitem" onclick={() => menu && startEdit(menu.t.id)}>Edit…</button>
        <button role="menuitem" onclick={() => (picking = true)}>Set credential…</button>
      {/if}
      {#if menu.t.kind === "folder"}
        <button role="menuitem" onclick={() => { if (menu) { shareTarget = { kind: "folder", id: menu.t.id, name: menu.t.name }; closeMenu(); } }}>Share…</button>
      {/if}
      {#if menu.t.kind === "cred"}
        <button role="menuitem" onclick={() => menu && startEditCred(menu.t.id)}>Edit…</button>
        <button role="menuitem" onclick={() => { if (menu) { shareTarget = { kind: "credential", id: menu.t.id, name: menu.t.name }; closeMenu(); } }}>Share…</button>
      {/if}
      <button role="menuitem" class="danger" onclick={() => (confirming = true)}>Delete…</button>
    {:else}
      <div class="confirm">
        {menu.t.kind === "folder"
          ? "Delete folder and its contents?"
          : menu.t.kind === "cred"
            ? "Delete this credential?"
            : "Delete this connection?"}
      </div>
      <button role="menuitem" class="danger" onclick={() => menu && doDelete(menu.t)}>Delete</button>
      <button role="menuitem" onclick={() => (confirming = false)}>Cancel</button>
    {/if}
  </div>
{/if}

<style>
  .pane {
    height: 100%;
    display: flex;
    flex-direction: column;
    background: var(--bg);
  }
  .search {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 10px;
    border-bottom: 1px solid var(--border);
    flex: 0 0 auto;
  }
  .search .ico {
    color: var(--text-mute);
    flex: 0 0 auto;
  }
  .search input {
    flex: 1;
    height: 26px;
    background: transparent;
    border: 0;
    outline: none;
    font-size: 13px;
  }
  .hint {
    flex: 0 0 auto;
    font-family: var(--mono);
    font-size: 11px;
    color: var(--text-mute);
    background: var(--bg-3);
    border: 1px solid var(--border);
    border-radius: 5px;
    padding: 2px 6px;
    cursor: pointer;
  }
  .hint:hover {
    color: var(--text-dim);
  }
  .add {
    flex: 0 0 auto;
    display: flex;
    align-items: center;
    justify-content: center;
    width: 26px;
    height: 26px;
    color: var(--text-mute);
    background: var(--bg-3);
    border: 1px solid var(--border);
    border-radius: 5px;
    cursor: pointer;
  }
  .add:hover {
    color: var(--accent);
    border-color: var(--accent);
  }
  .vault {
    flex: 0 0 auto;
    border-bottom: 1px solid var(--border);
    max-height: 34%;
    display: flex;
    flex-direction: column;
  }
  .vault-head {
    display: flex;
    align-items: center;
    gap: 7px;
    padding: 7px 10px 5px;
    flex: 0 0 auto;
  }
  .vault-ico {
    color: var(--rdp);
  }
  .vault-title {
    font-size: 11px;
    letter-spacing: 0.4px;
    text-transform: uppercase;
    color: var(--text-dim);
    font-weight: 600;
  }
  .vcount {
    font-family: var(--mono);
    font-size: 10.5px;
    color: var(--text-mute);
  }
  .vadd {
    margin-left: auto;
    display: flex;
    align-items: center;
    justify-content: center;
    width: 22px;
    height: 22px;
    color: var(--text-mute);
    background: transparent;
    border: 0;
    border-radius: 5px;
    cursor: pointer;
  }
  .vadd:hover {
    color: var(--rdp);
    background: var(--bg-2);
  }
  .vault-list {
    overflow: auto;
    padding-bottom: 4px;
  }
  .row.cred {
    padding-left: 10px;
  }
  .keyglyph {
    flex: 0 0 auto;
    color: var(--warn);
  }
  .vault-empty {
    padding: 4px 12px 8px;
    font-size: 11.5px;
    color: var(--text-mute);
  }
  .rows {
    flex: 1;
    overflow: auto;
    padding: 4px 0;
  }
  .row {
    display: flex;
    align-items: center;
    gap: 7px;
    width: 100%;
    height: var(--row-h);
    padding-right: 12px;
    background: transparent;
    border: 0;
    cursor: pointer;
    text-align: left;
    color: var(--text);
    font-size: 12.5px;
  }
  .row:hover {
    background: var(--bg-2);
  }
  .row.sel {
    background: var(--sel);
    box-shadow: inset 2px 0 0 var(--accent);
  }
  .row.drop {
    background: color-mix(in srgb, var(--accent) 20%, transparent);
    box-shadow: inset 0 0 0 1px var(--accent);
  }
  .rename {
    flex: 1;
    min-width: 0;
    height: 20px;
    background: var(--bg);
    border: 1px solid var(--accent);
    border-radius: 4px;
    outline: none;
    color: var(--text);
    font-size: 12.5px;
    padding: 0 5px;
  }
  .chev {
    flex: 0 0 auto;
    width: 10px;
    color: var(--text-mute);
    font-size: 9px;
    transition: transform 0.1s;
    transform: rotate(0deg);
  }
  .chev.open {
    transform: rotate(90deg);
  }
  .chev.locked {
    color: var(--text-mute);
    text-align: center;
  }
  .fico {
    flex: 0 0 auto;
    color: var(--warn);
  }
  .fico.locked {
    color: var(--text-mute);
  }
  .fname {
    font-weight: 500;
  }
  .fname.restricted {
    color: var(--text-mute);
    font-style: italic;
  }
  .count {
    margin-left: auto;
    font-family: var(--mono);
    font-size: 10.5px;
    color: var(--text-mute);
  }
  .badge {
    flex: 0 0 auto;
    width: 30px;
    text-align: center;
    font-family: var(--mono);
    font-size: 9px;
    font-weight: 700;
    padding: 1px 0;
    border-radius: 3px;
  }
  .badge.ssh {
    color: var(--ssh);
    background: color-mix(in srgb, var(--ssh) 15%, transparent);
  }
  .badge.rdp {
    color: var(--rdp);
    background: color-mix(in srgb, var(--rdp) 15%, transparent);
  }
  .cname {
    color: var(--text);
  }
  .host {
    margin-left: auto;
    font-family: var(--mono);
    font-size: 11.5px;
    color: var(--text-dim);
  }
  .port {
    color: var(--text-mute);
  }
  .empty {
    padding: 30px;
    text-align: center;
    color: var(--text-mute);
    font-size: 12.5px;
  }
  .op-error {
    flex: 0 0 auto;
    margin: 0 8px 8px;
    padding: 7px 10px;
    background: color-mix(in srgb, var(--err) 15%, var(--bg-2));
    border: 1px solid color-mix(in srgb, var(--err) 40%, transparent);
    border-radius: 6px;
    color: var(--err);
    font-size: 11.5px;
  }
  .menu-overlay {
    position: fixed;
    inset: 0;
    z-index: 80;
    background: transparent;
    border: 0;
    padding: 0;
    cursor: default;
  }
  .menu {
    position: fixed;
    z-index: 81;
    min-width: 150px;
    background: var(--bg-2);
    border: 1px solid var(--border-2);
    border-radius: 8px;
    box-shadow: 0 12px 34px rgba(0, 0, 0, 0.5);
    padding: 4px;
    display: flex;
    flex-direction: column;
    gap: 1px;
  }
  .menu button {
    text-align: left;
    background: transparent;
    border: 0;
    border-radius: 5px;
    padding: 6px 9px;
    font-size: 12.5px;
    color: var(--text);
    cursor: pointer;
  }
  .menu button:hover {
    background: var(--sel);
  }
  .menu button.danger {
    color: var(--err);
  }
  .menu button.on {
    color: var(--accent);
  }
  .menu button.on::after {
    content: "✓";
    margin-left: auto;
    padding-left: 8px;
  }
  .menu button.on {
    display: flex;
  }
  .menu .confirm {
    padding: 6px 9px 4px;
    font-size: 11.5px;
    color: var(--text-dim);
    line-height: 1.3;
  }
  .menu .confirm.dim {
    color: var(--text-mute);
  }
  .credmark {
    flex: 0 0 auto;
    color: var(--accent);
    margin-left: 4px;
  }
  .shared-tag {
    flex: 0 0 auto;
    font-size: 9px;
    font-weight: 600;
    letter-spacing: 0.3px;
    text-transform: uppercase;
    padding: 1px 5px;
    border-radius: 3px;
    color: var(--accent);
    background: color-mix(in srgb, var(--accent) 16%, transparent);
    border: 1px solid color-mix(in srgb, var(--accent) 32%, transparent);
  }
</style>
