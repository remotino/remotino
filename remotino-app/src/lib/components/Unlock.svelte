<script lang="ts">
  import { ui } from "$lib/state.svelte";
  import * as api from "$lib/api";
  import { tree } from "$lib/tree.svelte";
  import SettingsModal from "./SettingsModal.svelte";

  let settingsOpen = $state(false);

  let firstRun = $state(false);
  let passphrase = $state("");
  let confirm = $state("");
  let error = $state("");
  let busy = $state(false);
  // The identity's public-key fingerprint. For a returning user it is known *before*
  // unlock - it comes from the public half stored in the clear - so it can confirm "this
  // is your identity" up front. On first run there is no identity yet, so it stays blank
  // until one is created.
  let fingerprint = $state<string | null>(null);

  // Default the mode from whether an identity exists, and prefill its fingerprint.
  $effect(() => {
    api.identityStatus().then((s) => {
      firstRun = !s.exists;
      fingerprint = s.fingerprint;
    });
  });

  async function submit(e: Event) {
    e.preventDefault();
    if (busy) return;
    if (passphrase.length < 1) {
      error = "Enter your passphrase.";
      return;
    }
    if (firstRun && passphrase !== confirm) {
      error = "Passphrases do not match.";
      return;
    }
    busy = true;
    error = "";
    ui.sqlWarning = null;
    try {
      const info = firstRun
        ? await api.createIdentity(passphrase)
        : await api.unlock(passphrase);
      fingerprint = info.fingerprint;
      // Load the tree before showing the shell, so the first paint is populated.
      tree.data = await api.loadTree();
      ui.unlock();
      // Non-blocking: warn if the SQL login is over-privileged (defeats append-only).
      api.checkSqlPrivileges().then((w) => (ui.sqlWarning = w)).catch(() => {});
    } catch (err) {
      error = String(err);
    } finally {
      busy = false;
    }
  }
</script>

<div class="wrap">
  <form class="card" onsubmit={submit}>
    <div class="brand">
      <span class="mark">›_</span>
      <span class="name">Remotino</span>
    </div>

    <h1>{firstRun ? "Create your identity" : "Unlock"}</h1>
    <p class="sub">
      {firstRun
        ? "Your passphrase seals a new identity. It is the only way in - there is no reset."
        : "Your passphrase unlocks your identity. Nothing else is stored."}
    </p>

    <label>
      <span class="lbl">Passphrase</span>
      <!-- svelte-ignore a11y_autofocus -->
      <input
        type="password"
        bind:value={passphrase}
        oninput={() => (error = "")}
        placeholder="your passphrase"
        autofocus
        spellcheck="false"
      />
    </label>

    {#if firstRun}
      <label>
        <span class="lbl">Confirm passphrase</span>
        <input
          type="password"
          bind:value={confirm}
          oninput={() => (error = "")}
          placeholder="repeat it"
          spellcheck="false"
        />
      </label>
    {/if}

    {#if error}
      <div class="err">{error}</div>
    {/if}

    <button type="submit" disabled={busy}>
      {busy ? "Working…" : firstRun ? "Create identity" : "Unlock"}
    </button>

    {#if fingerprint}
      <div class="fp">
        <span class="fp-lbl">{firstRun ? "New identity fingerprint" : "Identity fingerprint"}</span>
        <span class="fp-val">{fingerprint}</span>
        {#if firstRun}
          <span class="fp-note">Record this — it names your identity, and there is no reset.</span>
        {/if}
      </div>
    {/if}

    <button type="button" class="switch" onclick={() => (firstRun = !firstRun)}>
      {firstRun ? "I already have an identity" : "Create a new identity instead"}
    </button>
    <button type="button" class="switch" onclick={() => (settingsOpen = true)}>
      Connection settings
    </button>
  </form>
</div>

<SettingsModal bind:open={settingsOpen} />

<style>
  .wrap {
    height: 100%;
    display: flex;
    align-items: center;
    justify-content: center;
    background: radial-gradient(120% 80% at 50% -10%, var(--bg-2), var(--bg));
  }
  .card {
    width: 340px;
    display: flex;
    flex-direction: column;
    gap: 13px;
    padding: 30px 30px 22px;
    background: var(--bg-2);
    border: 1px solid var(--border);
    border-radius: 12px;
    box-shadow: 0 24px 60px rgba(0, 0, 0, 0.45);
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 4px;
  }
  .mark {
    font-family: var(--mono);
    font-weight: 700;
    color: var(--accent);
    font-size: 17px;
  }
  .name {
    font-weight: 600;
    letter-spacing: 0.2px;
  }
  h1 {
    margin: 0;
    font-size: 19px;
    font-weight: 600;
  }
  .sub {
    margin: 0 0 4px;
    font-size: 12px;
    line-height: 1.5;
    color: var(--text-dim);
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
  input {
    width: 100%;
    height: 34px;
    padding: 0 11px;
    background: var(--bg);
    border: 1px solid var(--border-2);
    border-radius: 7px;
    outline: none;
    font-family: var(--mono);
    letter-spacing: 2px;
  }
  input:focus {
    border-color: var(--accent);
  }
  input::placeholder {
    letter-spacing: 0;
    font-family: var(--ui);
  }
  button[type="submit"]:disabled {
    opacity: 0.6;
    cursor: default;
  }
  .err {
    font-size: 12px;
    color: var(--err);
  }
  button[type="submit"] {
    height: 36px;
    border: 0;
    border-radius: 7px;
    background: var(--accent);
    color: #04120a;
    font-weight: 600;
    cursor: pointer;
    margin-top: 2px;
  }
  button[type="submit"]:hover {
    filter: brightness(1.06);
  }
  .fp {
    display: flex;
    flex-direction: column;
    gap: 3px;
    align-items: center;
    margin-top: 6px;
    padding-top: 14px;
    border-top: 1px solid var(--border);
  }
  .fp-lbl {
    font-size: 10px;
    letter-spacing: 0.3px;
    text-transform: uppercase;
    color: var(--text-mute);
  }
  .fp-val {
    font-family: var(--mono);
    font-size: 13px;
    color: var(--text-dim);
    letter-spacing: 1px;
  }
  .fp-note {
    font-size: 10.5px;
    color: var(--text-mute);
    text-align: center;
    max-width: 220px;
    line-height: 1.4;
    margin-top: 2px;
  }
  .switch {
    background: none;
    border: 0;
    color: var(--text-mute);
    font-size: 11.5px;
    cursor: pointer;
    padding: 2px;
  }
  .switch:hover {
    color: var(--text-dim);
  }
</style>
