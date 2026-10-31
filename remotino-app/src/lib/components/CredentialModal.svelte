<script lang="ts">
  import * as api from "$lib/api";
  import { tree } from "$lib/tree.svelte";

  type EditCred = { id: string; name: string; kind: "rdp" | "ssh"; username: string; domain: string | null; isKey: boolean };
  let { open = $bindable(false), edit = null }: { open?: boolean; edit?: EditCred | null } = $props();

  let name = $state("");
  let kind = $state<"rdp" | "ssh">("ssh");
  let auth = $state<"password" | "key">("password");
  let username = $state("");
  let domain = $state("");
  let secret = $state("");
  let passphrase = $state("");
  let busy = $state(false);
  let error = $state("");
  // In edit mode the secret is kept unless the user opts to replace it.
  let changeSecret = $state(false);

  // Key auth is SSH-only; force back to password when switching to RDP.
  $effect(() => {
    if (kind === "rdp" && auth === "key") auth = "password";
  });

  $effect(() => {
    if (open) {
      error = "";
      secret = "";
      passphrase = "";
      changeSecret = false;
      if (edit) {
        name = edit.name;
        kind = edit.kind;
        username = edit.username;
        domain = edit.domain ?? "";
        auth = edit.isKey ? "key" : "password";
      } else {
        name = "";
        kind = "ssh";
        auth = "password";
        username = "";
        domain = "";
      }
    }
  });

  // Whether the secret fields are in play (always for new; only if replacing for edit).
  const secretActive = $derived(!edit || changeSecret);

  function close() {
    open = false;
  }

  async function save(e: Event) {
    e.preventDefault();
    if (busy) return;
    error = "";
    if (!name.trim()) {
      error = "Give the credential a name.";
      return;
    }
    if (auth === "password" && !username.trim()) {
      error = "Username is required for a password credential.";
      return;
    }
    if (secretActive && !secret.trim()) {
      error = auth === "key" ? "Paste the private key." : "Enter the password.";
      return;
    }
    try {
      busy = true;
      if (edit) {
        tree.data = await api.updateCredential({
          id: edit.id,
          name: name.trim(),
          kind,
          username: username.trim(),
          domain: domain.trim() || null,
          auth,
          // Empty secret => keep the existing one.
          secret: changeSecret ? secret : "",
          passphrase: passphrase || null,
        });
      } else {
        tree.data = await api.createCredential({
          name: name.trim(),
          kind,
          username: username.trim(),
          domain: domain.trim() || null,
          auth,
          secret,
          passphrase: passphrase || null,
        });
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
  <div class="modal" role="dialog" aria-label="Credential" tabindex="-1" onkeydown={onKey}>
    <div class="title">{edit ? "Edit credential" : "New credential"}</div>

    <form onsubmit={save}>
      <label>
        <span class="lbl">Name</span>
        <!-- svelte-ignore a11y_autofocus -->
        <input bind:value={name} placeholder="prod-admin" autofocus spellcheck="false" />
      </label>

      <div class="split">
        <label>
          <span class="lbl">Protocol</span>
          <div class="seg">
            <button type="button" class:on={kind === "ssh"} onclick={() => (kind = "ssh")}>SSH</button>
            <button type="button" class:on={kind === "rdp"} onclick={() => (kind = "rdp")}>RDP</button>
          </div>
        </label>
        {#if kind === "ssh" && secretActive}
          <label>
            <span class="lbl">Auth</span>
            <div class="seg">
              <button type="button" class:on={auth === "password"} onclick={() => (auth = "password")}>Password</button>
              <button type="button" class:on={auth === "key"} onclick={() => (auth = "key")}>Key</button>
            </div>
          </label>
        {/if}
      </div>

      <div class="split">
        <label class="grow">
          <span class="lbl">Username</span>
          <input bind:value={username} placeholder={kind === "rdp" ? "administrator" : "root"} spellcheck="false" autocomplete="off" />
        </label>
        {#if kind === "rdp"}
          <label class="dom">
            <span class="lbl">Domain</span>
            <input bind:value={domain} placeholder="CORP" spellcheck="false" autocomplete="off" />
          </label>
        {/if}
      </div>

      {#if edit}
        <label class="chk">
          <input type="checkbox" bind:checked={changeSecret} />
          <span>Change {auth === "key" ? "key" : "password"}</span>
        </label>
      {/if}

      {#if secretActive}
        {#if auth === "key"}
          <label>
            <span class="lbl">Private key (OpenSSH)</span>
            <textarea
              bind:value={secret}
              rows="5"
              placeholder="-----BEGIN OPENSSH PRIVATE KEY-----&#10;…"
              spellcheck="false"
            ></textarea>
          </label>
          <label>
            <span class="lbl">Passphrase (optional)</span>
            <input type="password" bind:value={passphrase} placeholder="key passphrase" autocomplete="off" />
          </label>
        {:else}
          <label>
            <span class="lbl">Password</span>
            <input type="password" bind:value={secret} placeholder="password" autocomplete="off" />
          </label>
        {/if}
      {/if}

      <p class="note">Stored in your vault, sealed to your identity. Never leaves this machine in the clear.</p>

      {#if error}
        <div class="err">{error}</div>
      {/if}

      <div class="actions">
        <button type="button" class="ghost" onclick={close}>Cancel</button>
        <button type="submit" class="primary" disabled={busy}>{busy ? "Saving…" : edit ? "Save changes" : "Add credential"}</button>
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
    top: 9vh;
    left: 50%;
    transform: translateX(-50%);
    width: min(460px, 94%);
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
    margin-bottom: 14px;
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
  input {
    height: 32px;
    padding: 0 10px;
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
  .split {
    display: flex;
    gap: 10px;
  }
  .split > label {
    flex: 1;
  }
  .grow {
    flex: 1;
  }
  .dom {
    flex: 0 0 120px;
  }
  .seg {
    display: flex;
    gap: 2px;
    padding: 2px;
    height: 32px;
    box-sizing: border-box;
    background: var(--bg-inset);
    border: 1px solid var(--border);
    border-radius: 8px;
  }
  .seg button {
    flex: 1;
    background: transparent;
    border: 0;
    border-radius: 6px;
    color: var(--text-dim);
    font-size: 12px;
    cursor: pointer;
  }
  .seg button.on {
    background: var(--bg);
    color: var(--text);
  }
  .note {
    margin: 0;
    font-size: 11px;
    line-height: 1.4;
    color: var(--text-mute);
  }
  .chk {
    display: flex;
    align-items: center;
    gap: 7px;
    font-size: 12.5px;
    color: var(--text-dim);
    cursor: pointer;
  }
  .chk input {
    width: auto;
    height: auto;
    margin: 0;
  }
  .err {
    font-size: 12px;
    color: var(--err);
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
    opacity: 0.6;
    cursor: default;
  }
</style>
