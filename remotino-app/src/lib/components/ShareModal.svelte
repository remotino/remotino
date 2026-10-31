<script lang="ts">
  import * as api from "$lib/api";

  // What to share: a folder or a credential. Null closes the modal.
  export type ShareTarget = { kind: "folder" | "credential"; id: string; name: string };
  let { target = $bindable<ShareTarget | null>(null) }: {
    target?: ShareTarget | null;
  } = $props();

  let users = $state<api.User[]>([]);
  let granted = $state<Set<string>>(new Set());
  let busy = $state<string | null>(null);
  let error = $state("");

  const grantees = (t: ShareTarget) =>
    t.kind === "folder" ? api.folderGrantees(t.id) : api.credentialGrantees(t.id);
  const grant = (t: ShareTarget, keyId: string) =>
    t.kind === "folder" ? api.grantFolder(t.id, keyId) : api.grantCredential(t.id, keyId);
  const revoke = (t: ShareTarget, keyId: string) =>
    t.kind === "folder" ? api.revokeFolder(t.id, keyId) : api.revokeCredential(t.id, keyId);

  $effect(() => {
    const t = target;
    if (t) {
      error = "";
      Promise.all([api.listUsers(), grantees(t)]).then(([u, g]) => {
        // Skip yourself — you already hold this, sharing to self is a no-op.
        users = u.filter((x) => !x.isSelf);
        granted = new Set(g);
      });
    }
  });

  function close() {
    target = null;
  }

  async function toggle(keyId: string) {
    const t = target;
    if (!t || busy) return;
    error = "";
    busy = keyId;
    try {
      const result = granted.has(keyId) ? await revoke(t, keyId) : await grant(t, keyId);
      granted = new Set(result);
    } catch (e) {
      error = String(e);
    } finally {
      busy = null;
    }
  }

  function onKey(e: KeyboardEvent) {
    if (e.key === "Escape") close();
  }
</script>

{#if target}
  <button class="overlay" onclick={close} aria-label="Cancel"></button>
  <div class="modal" role="dialog" aria-label="Share" tabindex="-1" onkeydown={onKey}>
    <div class="title">Share “{target.name}”</div>
    <p class="hint">
      {#if target.kind === "folder"}
        Granting wraps this folder's key to the user, so they can read its connections. Revoking is forward-only.
      {:else}
        Granting wraps this credential's key to the user, so they can use it to connect. Revoking is forward-only.
      {/if}
    </p>

    {#if users.length === 0}
      <p class="hint">No other users enrolled yet — enrol someone from Users first.</p>
    {:else}
      <div class="list">
        {#each users as u (u.keyId)}
          <button class="user" class:on={granted.has(u.keyId)} disabled={busy === u.keyId} onclick={() => toggle(u.keyId)}>
            <span class="check">{granted.has(u.keyId) ? "✓" : ""}</span>
            <span class="uname">{u.name}</span>
            <span class="ufp">{u.fingerprint}</span>
          </button>
        {/each}
      </div>
    {/if}

    {#if error}
      <div class="err">{error}</div>
    {/if}

    <div class="actions">
      <button class="ghost" onclick={close}>Done</button>
    </div>
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
    width: min(420px, 92%);
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
  }
  .hint {
    margin: 6px 0 12px;
    font-size: 11.5px;
    line-height: 1.4;
    color: var(--text-mute);
  }
  .list {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .user {
    display: flex;
    align-items: baseline;
    gap: 8px;
    width: 100%;
    padding: 7px 9px;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    cursor: pointer;
    text-align: left;
    color: var(--text-dim);
  }
  .user:hover {
    border-color: var(--border-2);
  }
  .user.on {
    color: var(--text);
    border-color: color-mix(in srgb, var(--accent) 45%, transparent);
  }
  .user:disabled {
    opacity: 0.6;
    cursor: default;
  }
  .check {
    width: 12px;
    color: var(--accent);
    font-size: 12px;
  }
  .uname {
    font-size: 13px;
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
    margin-top: 8px;
  }
  .actions {
    display: flex;
    justify-content: flex-end;
    margin-top: 12px;
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
</style>
