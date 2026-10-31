<script lang="ts">
  import * as api from "$lib/api";
  import { ui } from "$lib/state.svelte";
  import DbAdminModal from "./DbAdminModal.svelte";

  let { open = $bindable(false) }: { open?: boolean } = $props();

  let dbAdminOpen = $state(false);

  // Setup-code import: a code from an admin fills the connection and carries a password
  // already sealed to this identity, applied on save instead of a typed password.
  let setupCodeText = $state("");
  let pendingSealed = $state<string | null>(null);
  let codeMsg = $state("");

  let backend = $state<"local" | "sql" | "pg">("local");
  let host = $state("");
  let port = $state(1433);
  let instance = $state("SQLEXPRESS");
  let database = $state("remotino");
  let trustCert = $state(false);
  let auth = $state<"integrated" | "sql">("integrated");
  // For a login, the setup code is the default path; manual user/password is the fallback.
  let credMode = $state<"code" | "manual">("code");
  let username = $state("");
  let password = $state("");

  // Postgres always authenticates with a login; the default port differs from SQL Server.
  function switchBackend(b: "local" | "sql" | "pg") {
    if (b === "pg" && port === 1433) port = 5432;
    if (b === "sql" && port === 5432) port = 1433;
    backend = b;
  }
  // Whether a password is already sealed to the identity (so the field can be left blank).
  let passwordSaved = $state(false);

  // Postgres TLS (trust-on-first-use). `pinnedFingerprint` is the approved SHA-256 (hex).
  let requireTls = $state(false);
  let pinnedFingerprint = $state<string | null>(null);
  // The certificate-approval popup: null when closed, else its loading/result state.
  let certProbe = $state<
    null | { loading: boolean; info: api.CertInfo | null; error: string }
  >(null);

  let busy = $state(false);
  let error = $state("");
  let confirmingReset = $state(false);

  // The backend in effect when the modal opened, to detect a local→shared move (which offers
  // to bring the local bookmarks along).
  let initialBackend = $state<"local" | "sql" | "pg">("local");
  // When set, we're asking whether to copy the local store into the just-configured shared DB.
  let migratePrompt = $state<null | { folders: number; connections: number; credentials: number }>(null);
  let migrating = $state(false);
  // Bumped whenever the user starts editing (e.g. applies a setup code); a late async
  // profile load with a stale token is ignored, so user input always wins the race.
  let loadSeq = 0;

  $effect(() => {
    if (open) {
      error = "";
      confirmingReset = false;
      setupCodeText = "";
      pendingSealed = null;
      codeMsg = "";
      migratePrompt = null;
      migrating = false;
      const seq = ++loadSeq;
      api.getConnectionProfile().then((p) => {
        if (seq !== loadSeq) return; // superseded by user input while loading
        backend = p.backend;
        initialBackend = p.backend;
        if (p.backend === "sql") {
          host = p.host;
          port = p.port;
          instance = p.instance ?? "";
          database = p.database;
          trustCert = p.trustCert;
          auth = p.auth ?? "integrated";
          username = p.username ?? "";
          // Show the manual fields for a login that's already configured; otherwise default
          // to the setup-code path.
          credMode = p.username ? "manual" : "code";
          // The password is sealed at rest and never round-trips to the UI. Leave the field
          // blank; a saved one is kept unless the user types a new value.
          password = "";
          passwordSaved = !!p.passwordSealed || !!p.password;
        } else if (p.backend === "pg") {
          host = p.host;
          port = p.port;
          database = p.database;
          username = p.username ?? "";
          credMode = p.username ? "manual" : "code";
          password = "";
          passwordSaved = !!p.passwordSealed || !!p.password;
          requireTls = p.requireTls ?? false;
          pinnedFingerprint = p.pinnedFingerprint ?? null;
        }
      });
    }
  });

  function sqlProfile(): api.SqlProfile {
    return {
      host: host.trim(),
      port,
      instance: instance.trim() || null,
      database: database.trim(),
      trustCert,
      auth,
      username: auth === "sql" ? username.trim() || null : null,
      password: auth === "sql" ? password || null : null,
    };
  }

  function pgProfile(): api.PgProfile {
    return {
      host: host.trim(),
      port,
      database: database.trim(),
      username: username.trim() || null,
      password: password || null,
      requireTls,
      pinnedFingerprint,
    };
  }

  // Read the server's certificate and open the approval popup. Pinning nothing yet.
  async function verifyCertificate() {
    certProbe = { loading: true, info: null, error: "" };
    try {
      const info = await api.pgProbeCertificate(pgProfile());
      certProbe = { loading: false, info, error: "" };
    } catch (e) {
      certProbe = { loading: false, info: null, error: String(e) };
    }
  }

  function trustCertificate() {
    if (certProbe?.info) {
      pinnedFingerprint = certProbe.info.sha256Hex;
      requireTls = true;
    }
    certProbe = null;
  }

  function close() {
    open = false;
  }

  function applyCode() {
    error = "";
    codeMsg = "";
    try {
      const c = api.decodeSetupCode(setupCodeText);
      loadSeq++; // cancel any in-flight profile load so it can't overwrite these fields
      backend = c.backend === "pg" ? "pg" : "sql";
      host = c.host;
      port = c.port;
      database = c.database;
      username = c.login;
      password = "";
      if (c.backend === "pg") {
        credMode = "manual";
        requireTls = c.requireTls ?? false;
        pinnedFingerprint = c.pinnedFingerprint ?? null;
      } else {
        instance = c.instance ?? "";
        trustCert = c.trustCert ?? false;
        auth = "sql";
      }
      pendingSealed = c.sealedHex;
      codeMsg = `Ready to connect as ${c.login}. Click Save.`;
    } catch (e) {
      pendingSealed = null;
      error = String(e);
    }
  }

  async function save() {
    error = "";
    if (backend === "sql" && auth === "sql" && !username.trim()) {
      error = "Enter a SQL login name (or apply a setup code).";
      return;
    }
    if (backend === "pg" && !username.trim()) {
      error = "Enter a Postgres login name (or apply a setup code).";
      return;
    }
    try {
      busy = true;
      if (backend === "sql" && pendingSealed) {
        // A setup code carries a password already sealed to this identity.
        await api.importProvisionedLogin(sqlProfile(), pendingSealed);
      } else if (backend === "pg" && pendingSealed) {
        await api.pgImportProvisionedLogin(pgProfile(), pendingSealed);
      } else {
        let profile: api.ConnectionProfile;
        if (backend === "sql") profile = { backend: "sql", ...sqlProfile() };
        else if (backend === "pg") profile = { backend: "pg", ...pgProfile() };
        else profile = { backend: "local" };
        await api.setConnectionProfile(profile);
      }
      // Moving from the local store to a shared backend while logged in: if there are local
      // bookmarks, offer to bring them along before we lock. The live session is still the
      // local one here, so loadTree() reads the local counts.
      const toShared = backend === "sql" || backend === "pg";
      if (initialBackend === "local" && toShared && ui.screen === "app") {
        try {
          const t = await api.loadTree();
          if (t.folders.length + t.connections.length + t.credentials.length > 0) {
            migratePrompt = {
              folders: t.folders.length,
              connections: t.connections.length,
              credentials: t.credentials.length,
            };
            busy = false;
            return; // wait for the user's choice; finishSwitch() runs from the prompt
          }
        } catch {
          /* couldn't read local — just proceed with the switch */
        }
      }
      await finishSwitch();
    } catch (e) {
      error = String(e);
    } finally {
      busy = false;
    }
  }

  // Applies the backend switch: a change only takes effect on the next unlock, so lock now -
  // otherwise you'd keep writing to the old store without realising.
  async function finishSwitch() {
    close();
    if (ui.screen === "app") {
      await api.lock();
      ui.sessions = [];
      ui.activeTab = 0;
      ui.screen = "unlock";
    }
  }

  async function migrateThenSwitch() {
    error = "";
    migrating = true;
    try {
      await api.migrateLocalIntoShared();
      migratePrompt = null;
      await finishSwitch();
    } catch (e) {
      error = String(e);
      migrating = false;
    }
  }

  async function skipMigration() {
    migratePrompt = null;
    await finishSwitch();
  }

  async function resetApp() {
    error = "";
    try {
      busy = true;
      await api.resetApp(); // the backend restarts the process; we won't return
    } catch (e) {
      error = String(e);
      busy = false;
    }
  }

  function onKey(e: KeyboardEvent) {
    if (e.key === "Escape") close();
  }
</script>

{#if open}
  <button class="overlay" onclick={close} aria-label="Cancel"></button>
  <div class="modal" role="dialog" aria-label="Settings" tabindex="-1" onkeydown={onKey}>
    <div class="title">Connection</div>
    <p class="sub">Where your connections and vault live. Saving a change locks the app so you re-open on the chosen connection.</p>

    <div class="seg">
      <button class:on={backend === "local"} onclick={() => switchBackend("local")}>This machine</button>
      <button class:on={backend === "sql"} onclick={() => switchBackend("sql")}>SQL Server</button>
      <button class:on={backend === "pg"} onclick={() => switchBackend("pg")}>Postgres</button>
    </div>

    {#if backend === "local"}
      <p class="note">A local encrypted store on this machine only. No server needed.</p>
    {:else if backend === "sql"}
      <div class="split">
        <label class="grow">
          <span class="lbl">Host</span>
          <input bind:value={host} placeholder="db-server.corp" spellcheck="false" />
        </label>
        <label class="port">
          <span class="lbl">Port</span>
          <input type="number" bind:value={port} min="1" max="65535" />
        </label>
      </div>
      <div class="split">
        <label class="grow">
          <span class="lbl">Instance (optional)</span>
          <input bind:value={instance} placeholder="SQLEXPRESS" spellcheck="false" />
        </label>
        <label class="grow">
          <span class="lbl">Database</span>
          <input bind:value={database} placeholder="remotino" spellcheck="false" />
        </label>
      </div>
      <label>
        <span class="lbl">Authentication</span>
        <div class="seg">
          <button type="button" class:on={auth === "integrated"} onclick={() => (auth = "integrated")}>Windows</button>
          <button type="button" class:on={auth === "sql"} onclick={() => (auth = "sql")}>SQL login</button>
        </div>
      </label>
      {#if auth === "sql"}
        {#if credMode === "code"}
          <label>
            <span class="lbl">Setup code</span>
            <textarea class="code-area" bind:value={setupCodeText} rows="3" placeholder="Paste the setup code from your admin…" spellcheck="false"></textarea>
          </label>
          <p class="note">The code fills in the connection and a password already sealed to your identity — nothing to type, and safe to receive over chat.</p>
          <div class="test-row">
            <button type="button" class="ghost" onclick={applyCode}>Apply code</button>
            {#if codeMsg}<span class="test-msg ok">{codeMsg}</span>{/if}
          </div>
          <button type="button" class="linkbtn" onclick={() => { credMode = "manual"; pendingSealed = null; codeMsg = ""; }}>Enter a username &amp; password instead</button>
        {:else}
          <div class="split">
            <label class="grow">
              <span class="lbl">Login</span>
              <input bind:value={username} placeholder="remotino_alice" spellcheck="false" autocomplete="off" />
            </label>
            <label class="grow">
              <span class="lbl">Password</span>
              <input type="password" bind:value={password} autocomplete="off" placeholder={passwordSaved ? "•••••• (saved — leave blank to keep)" : ""} />
            </label>
          </div>
          <button type="button" class="linkbtn" onclick={() => (credMode = "code")}>I have a setup code instead</button>
        {/if}
      {/if}

      <label class="chk">
        <input type="checkbox" bind:checked={trustCert} />
        <span>Trust the server certificate (self-signed) — LAN only</span>
      </label>
      <p class="note">
        {#if auth === "sql"}
          The password is sealed to your identity — unreadable without unlocking.
        {:else}
          Windows (integrated) authentication — no password stored.
        {/if}
      </p>

      <div class="test-row">
        <button type="button" class="ghost" onclick={() => (dbAdminOpen = true)}>Set up / add users…</button>
        <span class="test-msg">First-time setup, or provision logins for other users.</span>
      </div>
    {:else if backend === "pg"}
      <div class="split">
        <label class="grow">
          <span class="lbl">Host</span>
          <input bind:value={host} placeholder="db-server.corp" spellcheck="false" />
        </label>
        <label class="port">
          <span class="lbl">Port</span>
          <input type="number" bind:value={port} min="1" max="65535" />
        </label>
      </div>
      <label>
        <span class="lbl">Database</span>
        <input bind:value={database} placeholder="remotino" spellcheck="false" />
      </label>
      {#if credMode === "code"}
        <label>
          <span class="lbl">Setup code</span>
          <textarea class="code-area" bind:value={setupCodeText} rows="3" placeholder="Paste the setup code from your admin…" spellcheck="false"></textarea>
        </label>
        <p class="note">The code fills in the connection and a password already sealed to your identity — nothing to type, and safe to receive over chat.</p>
        <div class="test-row">
          <button type="button" class="ghost" onclick={applyCode}>Apply code</button>
          {#if codeMsg}<span class="test-msg ok">{codeMsg}</span>{/if}
        </div>
        <button type="button" class="linkbtn" onclick={() => { credMode = "manual"; pendingSealed = null; codeMsg = ""; }}>Enter a username &amp; password instead</button>
      {:else}
        <div class="split">
          <label class="grow">
            <span class="lbl">Login</span>
            <input bind:value={username} placeholder="remotino_alice" spellcheck="false" autocomplete="off" />
          </label>
          <label class="grow">
            <span class="lbl">Password</span>
            <input type="password" bind:value={password} autocomplete="off" placeholder={passwordSaved ? "•••••• (saved — leave blank to keep)" : ""} />
          </label>
        </div>
        <button type="button" class="linkbtn" onclick={() => (credMode = "code")}>I have a setup code instead</button>
      {/if}
      <p class="note">The password is sealed to your identity — unreadable without unlocking.</p>

      <label class="chk">
        <input type="checkbox" bind:checked={requireTls} onchange={() => { if (!requireTls) certProbe = null; }} />
        <span>Require TLS (encrypt the connection)</span>
      </label>
      {#if requireTls}
        <div class="tls-row">
          {#if pinnedFingerprint}
            <span class="tls-ok">✓ Trusted certificate</span>
            <code class="fp">{pinnedFingerprint}</code>
            <button type="button" class="linkbtn" onclick={verifyCertificate}>Re-verify…</button>
          {:else}
            <span class="tls-warn">⚠ Certificate not trusted yet</span>
            <button type="button" class="ghost small" onclick={verifyCertificate}>Verify certificate…</button>
          {/if}
        </div>
        <p class="note">Trust-on-first-use: you approve the server's certificate once by its fingerprint, and any later change is rejected.</p>
      {/if}

      <div class="test-row">
        <button type="button" class="ghost" onclick={() => (dbAdminOpen = true)}>Set up / add users…</button>
        <span class="test-msg">First-time setup, or provision logins for other users.</span>
      </div>
    {/if}

    {#if error}
      <div class="err">{error}</div>
    {/if}

    <div class="danger-zone">
      {#if !confirmingReset}
        <button type="button" class="reset" onclick={() => (confirmingReset = true)}>Reset app…</button>
        <span class="danger-hint">Wipe this machine's identity, local store, and settings.</span>
      {:else}
        <div class="danger-confirm">
          <p>This <strong>permanently deletes</strong> this machine's identity, local connections, and settings, then restarts. It cannot be undone. (A shared SQL database is not touched.)</p>
          <div class="danger-actions">
            <button type="button" class="ghost" onclick={() => (confirmingReset = false)} disabled={busy}>Cancel</button>
            <button type="button" class="reset solid" onclick={resetApp} disabled={busy}>{busy ? "Resetting…" : "Delete everything & restart"}</button>
          </div>
        </div>
      {/if}
    </div>

    <div class="actions">
      <button type="button" class="ghost" onclick={close}>Cancel</button>
      <button type="button" class="primary" onclick={save} disabled={busy}>Save</button>
    </div>
  </div>

  <DbAdminModal bind:open={dbAdminOpen} backend={backend === "pg" ? "pg" : "sql"} {host} {port} {instance} {database} {trustCert} {requireTls} {pinnedFingerprint} />

  {#if certProbe}
    <button class="overlay cert-overlay" onclick={() => (certProbe = null)} aria-label="Cancel"></button>
    <div class="modal cert-modal" role="dialog" aria-label="Trust certificate" tabindex="-1">
      <div class="title">Trust this server certificate?</div>
      {#if certProbe.loading}
        <p class="sub">Reading the server's certificate…</p>
      {:else if certProbe.error}
        <p class="sub">Couldn't read a certificate from that server.</p>
        <div class="err">{certProbe.error}</div>
        <div class="actions">
          <button type="button" class="ghost" onclick={() => (certProbe = null)}>Close</button>
          <button type="button" class="primary" onclick={verifyCertificate}>Retry</button>
        </div>
      {:else if certProbe.info}
        <p class="sub">Compare this fingerprint with the server's out-of-band. Approving pins it — any later change to the certificate is refused.</p>
        <div class="cert-fp">{certProbe.info.fingerprint}</div>
        <dl class="cert-meta">
          <dt>Subject</dt><dd>{certProbe.info.subject || "—"}</dd>
          <dt>Issuer</dt><dd>{certProbe.info.issuer || "—"}</dd>
          <dt>Valid from</dt><dd>{certProbe.info.notBefore || "—"}</dd>
          <dt>Valid until</dt><dd>{certProbe.info.notAfter || "—"}</dd>
        </dl>
        <div class="actions">
          <button type="button" class="ghost" onclick={() => (certProbe = null)}>Cancel</button>
          <button type="button" class="primary" onclick={trustCertificate}>Trust this certificate</button>
        </div>
      {/if}
    </div>
  {/if}

  {#if migratePrompt}
    <div class="overlay cert-overlay"></div>
    <div class="modal cert-modal" role="dialog" aria-label="Bring local bookmarks" tabindex="-1">
      <div class="title">Bring your bookmarks along?</div>
      <p class="sub">
        Your local store has
        {#if migratePrompt.connections}<b>{migratePrompt.connections} connection{migratePrompt.connections === 1 ? "" : "s"}</b>{/if}{#if migratePrompt.connections && (migratePrompt.credentials || migratePrompt.folders)}, {/if}{#if migratePrompt.credentials}<b>{migratePrompt.credentials} credential{migratePrompt.credentials === 1 ? "" : "s"}</b>{/if}{#if migratePrompt.credentials && migratePrompt.folders} and {/if}{#if migratePrompt.folders}<b>{migratePrompt.folders} folder{migratePrompt.folders === 1 ? "" : "s"}</b>{/if}. Copy them into the shared database so it isn't empty? They're re-created and re-encrypted on the shared repository; your local store is left untouched.
      </p>
      {#if error}<div class="err">{error}</div>{/if}
      <div class="actions">
        <button type="button" class="ghost" onclick={skipMigration} disabled={migrating}>Start fresh</button>
        <button type="button" class="primary" onclick={migrateThenSwitch} disabled={migrating}>{migrating ? "Copying…" : "Bring them along"}</button>
      </div>
    </div>
  {/if}
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
    top: 12vh;
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
  }
  .sub {
    margin: 4px 0 14px;
    font-size: 12px;
    line-height: 1.5;
    color: var(--text-dim);
  }
  .seg {
    display: flex;
    gap: 2px;
    padding: 2px;
    background: var(--bg-inset);
    border: 1px solid var(--border);
    border-radius: 8px;
    margin-bottom: 12px;
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
  .split {
    display: flex;
    gap: 10px;
    margin-bottom: 11px;
  }
  .grow {
    flex: 1;
  }
  .port {
    width: 84px;
    flex: 0 0 auto;
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
    box-sizing: border-box;
  }
  input:focus {
    border-color: var(--accent);
  }
  .chk {
    display: flex;
    align-items: center;
    gap: 7px;
    font-size: 12px;
    color: var(--text-dim);
    margin-bottom: 10px;
    cursor: pointer;
  }
  .chk input {
    width: auto;
    height: auto;
  }
  .note {
    margin: 0 0 12px;
    font-size: 11px;
    line-height: 1.4;
    color: var(--text-mute);
  }
  .test-row {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 4px;
  }
  .test-msg {
    font-size: 11.5px;
    color: var(--err);
  }
  .test-msg.ok {
    color: var(--ok);
  }
  .err {
    font-size: 12px;
    color: var(--err);
    margin-top: 6px;
  }
  .actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    margin-top: 12px;
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
  .primary:disabled,
  .ghost:disabled {
    opacity: 0.6;
    cursor: default;
  }
  .code-area {
    width: 100%;
    padding: 8px 10px;
    background: var(--bg);
    border: 1px solid var(--border-2);
    border-radius: 7px;
    outline: none;
    color: var(--text);
    font-family: var(--mono);
    font-size: 11px;
    line-height: 1.4;
    box-sizing: border-box;
    resize: vertical;
  }
  .code-area:focus {
    border-color: var(--accent);
  }
  .linkbtn {
    background: none;
    border: 0;
    padding: 2px 0;
    margin-top: 2px;
    color: var(--accent);
    font-size: 11.5px;
    cursor: pointer;
    align-self: flex-start;
  }
  .linkbtn:hover {
    text-decoration: underline;
  }
  .danger-zone {
    margin-top: 14px;
    padding-top: 12px;
    border-top: 1px solid var(--border);
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
  }
  .reset {
    height: 28px;
    padding: 0 12px;
    background: transparent;
    border: 1px solid color-mix(in srgb, var(--err) 45%, transparent);
    border-radius: 7px;
    color: var(--err);
    cursor: pointer;
    font-size: 12px;
  }
  .reset:hover {
    background: color-mix(in srgb, var(--err) 12%, transparent);
  }
  .reset.solid {
    background: var(--err);
    border-color: var(--err);
    color: #fff;
    height: 30px;
  }
  .danger-hint {
    font-size: 11px;
    color: var(--text-mute);
  }
  .danger-confirm {
    width: 100%;
  }
  .danger-confirm p {
    margin: 0 0 10px;
    font-size: 12px;
    line-height: 1.5;
    color: var(--text-dim);
  }
  .danger-actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
  }
  .tls-row {
    display: flex;
    align-items: center;
    gap: 9px;
    flex-wrap: wrap;
    margin-bottom: 8px;
  }
  .tls-ok {
    font-size: 12px;
    color: var(--ok);
  }
  .tls-warn {
    font-size: 12px;
    color: var(--err);
  }
  .fp {
    font-family: var(--mono);
    font-size: 10.5px;
    color: var(--text-dim);
    word-break: break-all;
    flex: 1 1 180px;
    min-width: 0;
  }
  .ghost.small {
    height: 27px;
    padding: 0 11px;
    font-size: 11.5px;
  }
  .cert-overlay {
    z-index: 78;
  }
  .cert-modal {
    z-index: 79;
    top: 16vh;
  }
  .cert-fp {
    font-family: var(--mono);
    font-size: 12.5px;
    font-weight: 600;
    letter-spacing: 0.4px;
    color: var(--text);
    background: var(--bg-inset);
    border: 1px solid var(--border-2);
    border-radius: 7px;
    padding: 10px 11px;
    word-break: break-all;
    line-height: 1.5;
    margin-bottom: 12px;
  }
  .cert-meta {
    display: grid;
    grid-template-columns: auto 1fr;
    gap: 4px 12px;
    margin: 0 0 14px;
    font-size: 11.5px;
  }
  .cert-meta dt {
    color: var(--text-mute);
    text-transform: uppercase;
    letter-spacing: 0.3px;
    font-size: 10.5px;
    padding-top: 1px;
  }
  .cert-meta dd {
    margin: 0;
    color: var(--text-dim);
    word-break: break-word;
  }
</style>
