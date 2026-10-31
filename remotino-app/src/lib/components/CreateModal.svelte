<script lang="ts">
  import { tree, type Folder } from "$lib/tree.svelte";
  import * as api from "$lib/api";

  // The parent owns visibility; we drive the rest. `preselect` is the folder the user had
  // selected in the tree, so "new connection" lands where they were looking.
  // `edit` (a connection) switches the modal to editing that connection in place.
  type EditConn = { id: string; kind: "rdp" | "ssh"; name: string; host: string; port: number };
  let {
    open = $bindable(false),
    preselect = null,
    edit = null,
  }: { open?: boolean; preselect?: string | null; edit?: EditConn | null } = $props();

  type Mode = "connection" | "folder";
  let mode = $state<Mode>("connection");
  let busy = $state(false);
  let error = $state("");

  // Connection fields.
  let folder = $state("");
  let kind = $state<"rdp" | "ssh">("ssh");
  let name = $state("");
  let host = $state("");
  let port = $state(22);
  let portTouched = $state(false);

  // Folder fields.
  let folderName = $state("");
  let folderParent = $state<string>("");

  // Only folders whose key this identity holds can receive writes; Restricted folders
  // cannot, so they are not offered as a target.
  const writable = $derived<Folder[]>(tree.data.folders.filter((f) => f.readable));

  // Default the port from the kind until the user overrides it.
  $effect(() => {
    if (!portTouched) port = kind === "rdp" ? 3389 : 22;
  });

  // Reset the form each time the modal opens (or prefill it, when editing).
  $effect(() => {
    if (open) {
      mode = "connection";
      error = "";
      folderName = "";
      folderParent = "";
      if (edit) {
        name = edit.name;
        host = edit.host;
        kind = edit.kind;
        port = edit.port;
        portTouched = true; // keep the existing port, don't snap to the protocol default
      } else {
        name = "";
        host = "";
        portTouched = false;
        kind = "ssh";
        // Preselect the writable folder the user had highlighted, else the first one.
        const canWrite = writable.some((f) => f.id === preselect);
        folder = canWrite ? (preselect as string) : (writable[0]?.id ?? "");
      }
    }
  });

  function close() {
    open = false;
  }

  async function save(e: Event) {
    e.preventDefault();
    if (busy) return;
    error = "";
    try {
      busy = true;
      if (mode === "connection") {
        if (!name.trim() || !host.trim()) {
          error = "Name and host are required.";
          return;
        }
        if (edit) {
          tree.data = await api.updateConnection(edit.id, {
            name: name.trim(),
            kind,
            host: host.trim(),
            port,
          });
        } else {
          if (!folder) {
            error = "Pick a folder. You can only add to folders you can open.";
            return;
          }
          tree.data = await api.createConnection({
            folder,
            kind,
            name: name.trim(),
            host: host.trim(),
            port,
          });
        }
      } else {
        if (!folderName.trim()) {
          error = "Give the folder a name.";
          return;
        }
        tree.data = await api.createFolder(
          folderName.trim(),
          folderParent || null,
        );
      }
      close();
    } catch (err) {
      error = String(err);
    } finally {
      busy = false;
    }
  }

  function onKey(e: KeyboardEvent) {
    if (e.key === "Escape") close();
  }
</script>

{#if open}
  <button class="overlay" onclick={close} aria-label="Cancel"></button>
  <div class="modal" role="dialog" aria-label="Create" tabindex="-1" onkeydown={onKey}>
    {#if edit}
      <div class="edit-title">Edit connection</div>
    {:else}
      <div class="seg">
        <button class:on={mode === "connection"} onclick={() => (mode = "connection")}>
          Connection
        </button>
        <button class:on={mode === "folder"} onclick={() => (mode = "folder")}>
          Folder
        </button>
      </div>
    {/if}

    <form onsubmit={save}>
      {#if mode === "connection"}
        {#if !edit}
          <label>
            <span class="lbl">Folder</span>
            {#if writable.length === 0}
              <div class="note">No writable folder yet. Create one first.</div>
            {:else}
              <select bind:value={folder}>
                {#each writable as f (f.id)}
                  <option value={f.id}>{f.name}</option>
                {/each}
              </select>
            {/if}
          </label>
        {/if}

        <label>
          <span class="lbl">Protocol</span>
          <div class="seg small">
            <button type="button" class:on={kind === "ssh"} onclick={() => (kind = "ssh")}>SSH</button>
            <button type="button" class:on={kind === "rdp"} onclick={() => (kind = "rdp")}>RDP</button>
          </div>
        </label>

        <label>
          <span class="lbl">Name</span>
          <!-- svelte-ignore a11y_autofocus -->
          <input bind:value={name} placeholder="db-prod-01" autofocus spellcheck="false" />
        </label>

        <div class="split">
          <label class="grow">
            <span class="lbl">Host</span>
            <input bind:value={host} placeholder="db-prod-01.internal" spellcheck="false" />
          </label>
          <label class="port">
            <span class="lbl">Port</span>
            <input
              type="number"
              bind:value={port}
              oninput={() => (portTouched = true)}
              min="1"
              max="65535"
            />
          </label>
        </div>
      {:else}
        <label>
          <span class="lbl">Name</span>
          <!-- svelte-ignore a11y_autofocus -->
          <input bind:value={folderName} placeholder="Production" autofocus spellcheck="false" />
        </label>
        <label>
          <span class="lbl">Parent</span>
          <select bind:value={folderParent}>
            <option value="">— none (top level) —</option>
            {#each writable as f (f.id)}
              <option value={f.id}>{f.name}</option>
            {/each}
          </select>
        </label>
      {/if}

      {#if error}
        <div class="err">{error}</div>
      {/if}

      <div class="actions">
        <button type="button" class="ghost" onclick={close}>Cancel</button>
        <button type="submit" class="primary" disabled={busy}>
          {busy
            ? "Saving…"
            : edit
              ? "Save changes"
              : mode === "connection"
                ? "Add connection"
                : "Create folder"}
        </button>
      </div>
    </form>
  </div>
{/if}

<style>
  .overlay {
    position: fixed;
    inset: 0;
    z-index: 70;
    background: var(--overlay);
    border: 0;
    padding: 0;
    cursor: default;
    animation: rt-fade 0.1s;
  }
  .modal {
    position: fixed;
    z-index: 71;
    top: 13vh;
    left: 50%;
    transform: translateX(-50%);
    width: min(440px, 92%);
    background: var(--bg-2);
    border: 1px solid var(--border-2);
    border-radius: 11px;
    box-shadow: 0 24px 60px rgba(0, 0, 0, 0.5);
    padding: 16px;
    animation: rt-pop 0.12s;
  }
  .seg {
    display: flex;
    gap: 2px;
    padding: 2px;
    background: var(--bg-inset);
    border: 1px solid var(--border);
    border-radius: 8px;
  }
  .seg button {
    flex: 1;
    height: 28px;
    background: transparent;
    border: 0;
    border-radius: 6px;
    color: var(--text-dim);
    font-size: 12.5px;
    cursor: pointer;
  }
  .seg button.on {
    background: var(--bg);
    color: var(--text);
  }
  .seg.small {
    width: 130px;
  }
  .edit-title {
    font-size: 14px;
    font-weight: 600;
  }
  form {
    display: flex;
    flex-direction: column;
    gap: 11px;
    margin-top: 14px;
  }
  label {
    display: block;
  }
  .lbl {
    display: block;
    font-size: 11px;
    letter-spacing: 0.3px;
    text-transform: uppercase;
    color: var(--text-mute);
    margin-bottom: 5px;
  }
  input,
  select {
    width: 100%;
    height: 32px;
    padding: 0 10px;
    background: var(--bg);
    border: 1px solid var(--border-2);
    border-radius: 7px;
    outline: none;
    color: var(--text);
    font-size: 13px;
  }
  input:focus,
  select:focus {
    border-color: var(--accent);
  }
  .split {
    display: flex;
    gap: 10px;
  }
  .grow {
    flex: 1;
  }
  .port {
    width: 92px;
    flex: 0 0 auto;
  }
  .port input {
    font-family: var(--mono);
  }
  .note {
    font-size: 12px;
    color: var(--text-mute);
    padding: 6px 0;
  }
  .err {
    font-size: 12px;
    color: var(--err);
  }
  .actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    margin-top: 4px;
  }
  .ghost {
    height: 32px;
    padding: 0 14px;
    background: transparent;
    border: 1px solid var(--border-2);
    border-radius: 7px;
    color: var(--text-dim);
    cursor: pointer;
    font-size: 12.5px;
  }
  .ghost:hover {
    color: var(--text);
  }
  .primary {
    height: 32px;
    padding: 0 14px;
    border: 0;
    border-radius: 7px;
    background: var(--accent);
    color: #04120a;
    font-weight: 600;
    cursor: pointer;
    font-size: 12.5px;
  }
  .primary:hover {
    filter: brightness(1.06);
  }
  .primary:disabled {
    opacity: 0.6;
    cursor: default;
  }
</style>
