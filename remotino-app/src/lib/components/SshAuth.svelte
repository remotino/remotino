<script lang="ts">
  import { ui } from "$lib/state.svelte";
  import { stashSsh } from "$lib/sshpending";

  // Bound to ui.connectTarget: non-null means "prompt for this connection's credentials".
  const target = $derived(ui.connectTarget);

  let username = $state("");
  let password = $state("");

  // Reset fields whenever a new target appears.
  $effect(() => {
    if (target) {
      username = "";
      password = "";
    }
  });

  function cancel() {
    ui.connectTarget = null;
  }

  function connect(e: Event) {
    e.preventDefault();
    const c = target;
    if (!c || !username.trim()) return;

    // A fresh id for this live session; the terminal picks up the credentials by it and
    // opens the connection. The password is handed off out-of-band (sshpending), not put
    // into the tab state.
    const id = crypto.randomUUID();
    stashSsh(id, {
      host: c.host,
      port: c.port,
      username: username.trim(),
      password,
    });
    ui.openSession({ id, name: c.name, kind: c.kind, status: "connecting", host: c.host });
    ui.connectTarget = null;
  }

  function onKey(e: KeyboardEvent) {
    if (e.key === "Escape") cancel();
  }
</script>

{#if target}
  <button class="overlay" onclick={cancel} aria-label="Cancel"></button>
  <div class="modal" role="dialog" aria-label="Credentials" tabindex="-1" onkeydown={onKey}>
    <div class="head">
      <span class="badge {target.kind}">{target.kind.toUpperCase()}</span>
      <div class="who">
        <div class="name">{target.name}</div>
        <div class="addr">{target.host}<span class="port">:{target.port}</span></div>
      </div>
    </div>

    <form onsubmit={connect}>
      <label>
        <span class="lbl">Username</span>
        <!-- svelte-ignore a11y_autofocus -->
        <input bind:value={username} placeholder="root" autofocus spellcheck="false" autocomplete="off" />
      </label>
      <label>
        <span class="lbl">Password</span>
        <input type="password" bind:value={password} placeholder="password" autocomplete="off" />
      </label>

      <p class="note">
        Used once to connect. It is not stored — the credential vault will handle this later.
      </p>

      <div class="actions">
        <button type="button" class="ghost" onclick={cancel}>Cancel</button>
        <button type="submit" class="primary" disabled={!username.trim()}>Connect</button>
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
    top: 15vh;
    left: 50%;
    transform: translateX(-50%);
    width: min(400px, 92%);
    background: var(--bg-2);
    border: 1px solid var(--border-2);
    border-radius: 11px;
    box-shadow: 0 24px 60px rgba(0, 0, 0, 0.5);
    padding: 16px;
    animation: rt-pop 0.12s;
  }
  .head {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 14px;
  }
  .badge {
    flex: 0 0 auto;
    text-align: center;
    font-family: var(--mono);
    font-size: 10px;
    font-weight: 700;
    padding: 3px 5px;
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
  .who .name {
    font-size: 14px;
    color: var(--text);
  }
  .who .addr {
    font-family: var(--mono);
    font-size: 12px;
    color: var(--text-dim);
  }
  .port {
    color: var(--text-mute);
  }
  form {
    display: flex;
    flex-direction: column;
    gap: 11px;
  }
  .lbl {
    display: block;
    font-size: 11px;
    letter-spacing: 0.3px;
    text-transform: uppercase;
    color: var(--text-mute);
    margin-bottom: 5px;
  }
  input {
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
  input:focus {
    border-color: var(--accent);
  }
  .note {
    margin: 0;
    font-size: 11px;
    line-height: 1.4;
    color: var(--text-mute);
  }
  .actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    margin-top: 2px;
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
    opacity: 0.5;
    cursor: default;
  }
</style>
