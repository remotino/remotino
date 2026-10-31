<script lang="ts">
  import * as api from "$lib/api";
  import DbAdminModal from "./DbAdminModal.svelte";

  let { open = $bindable(false) }: { open?: boolean } = $props();

  // Provisioning a setup code for an enrolled user, without leaving this modal.
  let dbAdminOpen = $state(false);
  let provisionTarget = $state<string | null>(null);

  function makeSetupCode(keyId: string) {
    provisionTarget = keyId;
    dbAdminOpen = true;
  }

  let myIdentity = $state("");
  let copied = $state(false);
  let users = $state<api.User[]>([]);

  let myDisplayName = $state("");
  let savingName = $state(false);
  let nameSaved = $state(false);
  let name = $state("");
  let paste = $state("");
  let busy = $state(false);
  let error = $state("");

  $effect(() => {
    if (open) {
      error = "";
      name = "";
      paste = "";
      copied = false;
      nameSaved = false;
      api.myPublicIdentity().then((s) => (myIdentity = s));
      api.myName().then((n) => (myDisplayName = n));
      api.listUsers().then((u) => (users = u));
    }
  });

  function close() {
    open = false;
  }

  async function saveName() {
    error = "";
    if (!myDisplayName.trim()) {
      error = "Enter a display name so others can find you.";
      return;
    }
    try {
      savingName = true;
      users = await api.setMyName(myDisplayName.trim());
      nameSaved = true;
      setTimeout(() => (nameSaved = false), 1500);
    } catch (e) {
      error = String(e);
    } finally {
      savingName = false;
    }
  }

  async function copyMine() {
    try {
      await navigator.clipboard.writeText(myIdentity);
      copied = true;
      setTimeout(() => (copied = false), 1500);
    } catch {
      /* clipboard blocked */
    }
  }

  async function enroll() {
    error = "";
    if (!name.trim() || !paste.trim()) {
      error = "A name and the person's identity are both required.";
      return;
    }
    try {
      busy = true;
      users = await api.enrollUser(name.trim(), paste.trim());
      name = "";
      paste = "";
    } catch (e) {
      error = String(e);
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
  <div class="modal" role="dialog" aria-label="Users" tabindex="-1" onkeydown={onKey}>
    <div class="title">Users</div>

    <div class="section">
      <span class="lbl">Your identity</span>
      <p class="hint">Send this to whoever administers the shared repository so they can enrol you.</p>
      <div class="mine">
        <code class="fp">{myIdentity ? myIdentity.slice(0, 20) + "…" : "…"}</code>
        <button class="ghost" onclick={copyMine}>{copied ? "Copied" : "Copy"}</button>
      </div>
    </div>

    <div class="section">
      <span class="lbl">Your display name</span>
      <p class="hint">Publish yourself under this name so others can share folders and credentials <em>back</em> to you. Republished automatically each time you unlock.</p>
      <div class="mine">
        <input class="grow" bind:value={myDisplayName} placeholder="e.g. Admin" spellcheck="false" />
        <button class="ghost" onclick={saveName} disabled={savingName}>{nameSaved ? "Saved" : savingName ? "…" : "Publish"}</button>
      </div>
    </div>

    <div class="section">
      <span class="lbl">Enrol a user</span>
      <input bind:value={name} placeholder="Name (e.g. Bob)" spellcheck="false" />
      <textarea bind:value={paste} rows="3" placeholder="Paste their identity string…" spellcheck="false"></textarea>
      <button class="primary" onclick={enroll} disabled={busy}>{busy ? "Enrolling…" : "Enrol"}</button>
    </div>

    <div class="section">
      <span class="lbl">Enrolled users</span>
      {#if users.length === 0}
        <p class="hint">No one enrolled yet.</p>
      {:else}
        <div class="list">
          {#each users as u (u.keyId)}
            <div class="user">
              <span class="uname">{u.name}{#if u.isSelf} <span class="you">(you)</span>{/if}</span>
              <span class="ufp">{u.fingerprint}</span>
              {#if !u.isSelf}
                <button class="codebtn" onclick={() => makeSetupCode(u.keyId)} title="Provision a SQL login and generate a setup code for this user">Setup code</button>
              {/if}
            </div>
          {/each}
        </div>
      {/if}
    </div>

    {#if error}
      <div class="err">{error}</div>
    {/if}

    <div class="actions">
      <button class="ghost" onclick={close}>Close</button>
    </div>
  </div>

  <DbAdminModal bind:open={dbAdminOpen} preselect={provisionTarget} />
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
    top: 9vh;
    left: 50%;
    transform: translateX(-50%);
    width: min(460px, 94%);
    max-height: 82vh;
    overflow: auto;
    background: var(--bg-2);
    border: 1px solid var(--border-2);
    border-radius: 11px;
    box-shadow: 0 24px 60px rgba(0, 0, 0, 0.5);
    padding: 16px;
    animation: rt-pop 0.12s;
  }
  .title {
    font-size: 14px;
    font-weight: 600;
    margin-bottom: 12px;
  }
  .section {
    margin-bottom: 16px;
    display: flex;
    flex-direction: column;
    gap: 7px;
  }
  .lbl {
    font-size: 11px;
    letter-spacing: 0.3px;
    text-transform: uppercase;
    color: var(--text-mute);
  }
  .hint {
    margin: 0;
    font-size: 11.5px;
    line-height: 1.4;
    color: var(--text-mute);
  }
  .mine {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .mine .grow {
    flex: 1;
    width: auto;
  }
  .you {
    color: var(--text-mute);
    font-size: 11px;
  }
  .codebtn {
    flex: 0 0 auto;
    height: 22px;
    padding: 0 9px;
    background: transparent;
    border: 1px solid color-mix(in srgb, var(--accent) 40%, transparent);
    border-radius: 6px;
    color: var(--accent);
    font-size: 11px;
    cursor: pointer;
  }
  .codebtn:hover {
    background: color-mix(in srgb, var(--accent) 12%, transparent);
  }
  .fp {
    flex: 1;
    font-family: var(--mono);
    font-size: 12px;
    color: var(--text-dim);
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 6px 9px;
    overflow: hidden;
  }
  input,
  textarea {
    width: 100%;
    padding: 7px 10px;
    background: var(--bg);
    border: 1px solid var(--border-2);
    border-radius: 7px;
    outline: none;
    color: var(--text);
    font-size: 13px;
    box-sizing: border-box;
  }
  textarea {
    resize: vertical;
    font-family: var(--mono);
    font-size: 11.5px;
    line-height: 1.4;
  }
  input:focus,
  textarea:focus {
    border-color: var(--accent);
  }
  .list {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .user {
    display: flex;
    align-items: baseline;
    gap: 9px;
    padding: 6px 9px;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 6px;
  }
  .uname {
    font-size: 13px;
    color: var(--text);
  }
  .ufp {
    margin-left: auto;
    font-family: var(--mono);
    font-size: 10.5px;
    color: var(--text-mute);
  }
  .err {
    font-size: 12px;
    color: var(--err);
    margin-bottom: 8px;
  }
  .actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
  }
  .ghost {
    height: 30px;
    padding: 0 13px;
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
    align-self: flex-start;
    padding: 0 14px;
    border: 0;
    border-radius: 7px;
    background: var(--accent);
    color: #04120a;
    font-weight: 600;
    cursor: pointer;
    font-size: 12.5px;
  }
  .primary:disabled {
    opacity: 0.6;
    cursor: default;
  }
</style>
