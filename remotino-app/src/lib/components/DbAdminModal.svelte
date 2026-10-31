<script lang="ts">
  import * as api from "$lib/api";
  import { ui, adminCreds } from "$lib/state.svelte";
  import { tree } from "$lib/tree.svelte";

  // Connection target. Passed from Settings (the live form); when opened elsewhere (e.g. the
  // Users modal) these are empty and we load them from the saved profile instead. `preselect`
  // is an enrolled user's keyId to provision for immediately.
  let {
    open = $bindable(false),
    backend = "sql",
    host = "",
    port = 1433,
    instance = "" as string,
    database = "remotino",
    trustCert = false,
    requireTls = false,
    pinnedFingerprint = null,
    preselect = null,
  }: {
    open?: boolean;
    backend?: "sql" | "pg";
    host?: string;
    port?: number;
    instance?: string;
    database?: string;
    trustCert?: boolean;
    requireTls?: boolean;
    pinnedFingerprint?: string | null;
    preselect?: string | null;
  } = $props();

  // Resolved connection context (props take precedence; else from the saved profile). Using
  // resolved state - not the raw props - means the modal works when opened from the Users panel
  // with no props: it reads the real backend + TLS from the saved profile instead of defaulting
  // to SQL Server (which would speak the wrong protocol at a Postgres server).
  let cBackend = $state<"sql" | "pg">("sql");
  let cHost = $state("");
  let cPort = $state(1433);
  let cInstance = $state("");
  let cDatabase = $state("remotino");
  let cTrustCert = $state(false);
  let cRequireTls = $state(false);
  let cPinned = $state<string | null>(null);

  const isPg = $derived(cBackend === "pg");
  const dbLabel = $derived(isPg ? "Postgres" : "SQL Server");

  // Transient admin sign-in — used for these operations only, never stored; cached in memory
  // so provisioning several users in a row doesn't re-prompt.
  let adminAuth = $state(adminCreds.auth);
  let adminUser = $state(adminCreds.user);
  let adminPass = $state(adminCreds.pass);
  $effect(() => {
    adminCreds.auth = adminAuth;
    adminCreds.user = adminUser;
    adminCreds.pass = adminPass;
  });

  let busy = $state(false);
  let initMsg = $state("");
  let initOk = $state(false);
  let error = $state("");
  let confirmingReset = $state(false);

  // Provisioning.
  let users = $state<api.User[]>([]);
  let target = $state<string | "self">("self"); // "self" or an enrolled user's keyId
  let loginName = $state("remotino_admin");
  let setupCode = $state(""); // the code to hand another user, after provisioning them
  let codeCopied = $state(false);
  let selfDone = $state(false);

  $effect(() => {
    if (open) {
      error = "";
      initMsg = "";
      setupCode = "";
      selfDone = false;
      confirmingReset = false;
      // Resolve connection context: props (Settings' live form) win; else the saved profile.
      if (host.trim()) {
        cBackend = backend;
        cHost = host;
        cPort = port;
        cInstance = instance ?? "";
        cDatabase = database;
        cTrustCert = trustCert;
        cRequireTls = requireTls;
        cPinned = pinnedFingerprint;
      } else {
        api.getConnectionProfile().then((p) => {
          if (p.backend === "sql") {
            cBackend = "sql";
            cHost = p.host;
            cPort = p.port;
            cInstance = p.instance ?? "";
            cDatabase = p.database;
            cTrustCert = p.trustCert;
          } else if (p.backend === "pg") {
            cBackend = "pg";
            cHost = p.host;
            cPort = p.port;
            cDatabase = p.database;
            cRequireTls = p.requireTls ?? false;
            cPinned = p.pinnedFingerprint ?? null;
          }
        });
      }
      api.listUsers().then((u) => {
        users = u.filter((x) => !x.isSelf);
        // Preselect a user if asked (from the Users modal's "Setup code" button).
        target = preselect && users.some((x) => x.keyId === preselect) ? preselect : "self";
        onTargetChange();
      });
    }
  });

  // Keep the login name in step with the chosen target unless the admin edited it.
  function slug(name: string): string {
    return name.toLowerCase().replace(/[^a-z0-9_]+/g, "_").replace(/^_+|_+$/g, "") || "user";
  }
  function onTargetChange() {
    setupCode = "";
    selfDone = false;
    if (target === "self") loginName = "remotino_admin";
    else {
      const u = users.find((x) => x.keyId === target);
      loginName = u ? `remotino_${slug(u.name)}` : "remotino_user";
    }
  }

  function adminProfile(): api.SqlProfile {
    return {
      host: cHost.trim(),
      port: cPort,
      instance: cInstance.trim() || null,
      database: cDatabase.trim(),
      trustCert: cTrustCert,
      auth: adminAuth,
      username: adminAuth === "sql" ? adminUser.trim() || null : null,
      password: adminAuth === "sql" ? adminPass || null : null,
    };
  }

  function connProfile(login: string): api.SqlProfile {
    return {
      host: cHost.trim(),
      port: cPort,
      instance: cInstance.trim() || null,
      database: cDatabase.trim(),
      trustCert: cTrustCert,
      auth: "sql",
      username: login,
      password: null,
    };
  }

  // Postgres always signs in with a superuser login (no integrated auth).
  function pgAdminProfile(): api.PgProfile {
    return {
      host: cHost.trim(),
      port: cPort,
      database: cDatabase.trim(),
      username: adminUser.trim() || null,
      password: adminPass || null,
      requireTls: cRequireTls,
      pinnedFingerprint: cPinned,
    };
  }

  function pgConnProfile(login: string): api.PgProfile {
    return {
      host: cHost.trim(),
      port: cPort,
      database: cDatabase.trim(),
      username: login,
      password: null,
      requireTls: cRequireTls,
      pinnedFingerprint: cPinned,
    };
  }

  function requireConn(): boolean {
    if (!cHost.trim() || !cDatabase.trim()) {
      error = "Set the host and database in Connection settings first.";
      return false;
    }
    return true;
  }

  async function initialize() {
    error = "";
    initMsg = "";
    if (!requireConn()) return;
    try {
      busy = true;
      if (isPg) await api.pgInitializeDatabase(pgAdminProfile());
      else await api.initializeDatabase(adminProfile());
      initOk = true;
      initMsg = "Database ready — tables, role and grants are in place.";
    } catch (e) {
      initOk = false;
      initMsg = String(e);
    } finally {
      busy = false;
    }
  }

  async function provision() {
    error = "";
    setupCode = "";
    selfDone = false;
    if (!requireConn()) return;
    if (!/^[A-Za-z0-9_]+$/.test(loginName)) {
      error = "Login name may only contain letters, numbers and underscores.";
      return;
    }
    try {
      busy = true;
      const grantee = target === "self" ? null : target;
      const result = isPg
        ? await api.pgProvisionLogin(pgAdminProfile(), loginName, grantee)
        : await api.provisionLogin(adminProfile(), loginName, grantee);
      if (target === "self") {
        // Apply immediately: switch our own profile to this least-privilege login.
        if (isPg) await api.pgImportProvisionedLogin(pgConnProfile(result.login), result.sealedHex);
        else await api.importProvisionedLogin(connProfile(result.login), result.sealedHex);
        selfDone = true;
      } else if (isPg) {
        setupCode = api.encodeSetupCode({
          backend: "pg",
          host: cHost.trim(),
          port: cPort,
          database: cDatabase.trim(),
          requireTls: cRequireTls,
          pinnedFingerprint: cPinned,
          login: result.login,
          sealedHex: result.sealedHex,
        });
      } else {
        setupCode = api.encodeSetupCode({
          backend: "sql",
          host: cHost.trim(),
          port: cPort,
          instance: cInstance.trim() || null,
          database: cDatabase.trim(),
          trustCert: cTrustCert,
          login: result.login,
          sealedHex: result.sealedHex,
        });
      }
    } catch (e) {
      error = String(e);
    } finally {
      busy = false;
    }
  }

  async function copyCode() {
    try {
      await navigator.clipboard.writeText(setupCode);
      codeCopied = true;
      setTimeout(() => (codeCopied = false), 1500);
    } catch {
      /* clipboard blocked */
    }
  }

  async function resetDb() {
    error = "";
    if (!requireConn()) return;
    try {
      busy = true;
      if (isPg) await api.pgResetDatabase(pgAdminProfile());
      else await api.resetDatabase(adminProfile());
      confirmingReset = false;
      if (ui.screen === "app") {
        // The backend re-opened our session on the fresh database (login re-provisioned),
        // so refresh the now-empty tree and close - no re-unlock needed.
        tree.data = await api.loadTree();
        ui.sqlWarning = null;
        open = false;
      } else {
        initOk = true;
        initMsg = "Database wiped and recreated — unlock to start clean.";
      }
    } catch (e) {
      error = String(e);
    } finally {
      busy = false;
    }
  }

  async function relock() {
    // Our own login changed; reconnect on it.
    await api.lock();
    ui.sessions = [];
    ui.activeTab = 0;
    ui.screen = "unlock";
    open = false;
  }

  function close() {
    open = false;
  }
  function onKey(e: KeyboardEvent) {
    if (e.key === "Escape") close();
  }
</script>

{#if open}
  <button class="overlay" onclick={close} aria-label="Cancel"></button>
  <div class="modal" role="dialog" aria-label="Database admin" tabindex="-1" onkeydown={onKey}>
    <div class="title">Set up the database</div>
    <p class="sub">Admin tasks for a shared {dbLabel}: create the schema, and hand out per-user logins. Uses admin rights <strong>once</strong> — nothing here is stored.</p>

    <div class="section">
      <span class="lbl">Admin sign-in</span>
      {#if isPg}
        <div class="split">
          <label class="grow">
            <span class="mini">Superuser</span>
            <input bind:value={adminUser} spellcheck="false" autocomplete="off" placeholder="postgres" />
          </label>
          <label class="grow">
            <span class="mini">Password</span>
            <input type="password" bind:value={adminPass} autocomplete="off" />
          </label>
        </div>
      {:else}
        <div class="seg">
          <button type="button" class:on={adminAuth === "integrated"} onclick={() => (adminAuth = "integrated")}>Windows</button>
          <button type="button" class:on={adminAuth === "sql"} onclick={() => (adminAuth = "sql")}>SQL admin (sa)</button>
        </div>
        {#if adminAuth === "sql"}
          <div class="split">
            <label class="grow">
              <span class="mini">Login</span>
              <input bind:value={adminUser} spellcheck="false" autocomplete="off" />
            </label>
            <label class="grow">
              <span class="mini">Password</span>
              <input type="password" bind:value={adminPass} autocomplete="off" />
            </label>
          </div>
        {/if}
      {/if}
    </div>

    <div class="section">
      <span class="lbl">1 · Initialize database</span>
      <p class="hint">Creates the <code>{cDatabase || "remotino"}</code> database if missing, then the tables, the <code>remotino_user</code> role and its SELECT/INSERT grants.</p>
      <div class="row">
        <button type="button" class="ghost" onclick={initialize} disabled={busy}>{busy ? "Working…" : "Initialize database"}</button>
        {#if initMsg}<span class="msg" class:ok={initOk}>{initMsg}</span>{/if}
      </div>
    </div>

    <div class="section">
      <span class="lbl">2 · Provision a login</span>
      <p class="hint">Creates a least-privilege {dbLabel} login with a random password sealed to that user's identity. No password is ever shown or typed.</p>
      <div class="split">
        <label class="grow">
          <span class="mini">For</span>
          <select bind:value={target} onchange={onTargetChange}>
            <option value="self">Yourself</option>
            {#each users as u (u.keyId)}
              <option value={u.keyId}>{u.name}</option>
            {/each}
          </select>
        </label>
        <label class="grow">
          <span class="mini">Login name</span>
          <input bind:value={loginName} spellcheck="false" autocomplete="off" />
        </label>
      </div>
      <div class="row">
        <button type="button" class="primary" onclick={provision} disabled={busy}>{busy ? "Working…" : "Create login"}</button>
      </div>

      {#if selfDone}
        <div class="done">
          Your own login <code>{loginName}</code> is set. Re-open the app to connect on it.
          <button type="button" class="ghost small" onclick={relock}>Lock &amp; reconnect</button>
        </div>
      {/if}

      {#if setupCode}
        <div class="code-box">
          <span class="mini">Setup code — send this to the user. They paste it under “I have a setup code”. It only unlocks for them.</span>
          <textarea readonly rows="3" value={setupCode}></textarea>
          <button type="button" class="ghost small" onclick={copyCode}>{codeCopied ? "Copied" : "Copy setup code"}</button>
        </div>
      {/if}
    </div>

    {#if error}
      <div class="err">{error}</div>
    {/if}

    <div class="danger-zone">
      {#if !confirmingReset}
        <button type="button" class="reset" onclick={() => (confirmingReset = true)}>Reset database…</button>
        <span class="danger-hint">Wipe the shared repository and recreate an empty schema.</span>
      {:else}
        <div class="danger-confirm">
          <p><strong>Permanently erases the entire shared database</strong> — every user, folder, credential and audit event, for everyone — then recreates an empty schema. This cannot be undone.</p>
          <div class="danger-actions">
            <button type="button" class="ghost" onclick={() => (confirmingReset = false)} disabled={busy}>Cancel</button>
            <button type="button" class="reset solid" onclick={resetDb} disabled={busy}>{busy ? "Wiping…" : "Wipe & recreate"}</button>
          </div>
        </div>
      {/if}
    </div>

    <div class="actions">
      <button type="button" class="ghost" onclick={close}>Done</button>
    </div>
  </div>
{/if}

<style>
  .overlay {
    position: fixed;
    inset: 0;
    z-index: 74;
    background: var(--overlay);
    border: 0;
    padding: 0;
    cursor: default;
    animation: rt-fade 0.1s;
  }
  .modal {
    position: fixed;
    z-index: 75;
    top: 8vh;
    left: 50%;
    transform: translateX(-50%);
    width: min(500px, 94%);
    max-height: 84vh;
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
  }
  .sub {
    margin: 4px 0 14px;
    font-size: 12px;
    line-height: 1.5;
    color: var(--text-dim);
  }
  .section {
    margin-bottom: 16px;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .lbl {
    font-size: 11px;
    letter-spacing: 0.3px;
    text-transform: uppercase;
    color: var(--text-mute);
    font-weight: 600;
  }
  .mini {
    display: block;
    font-size: 10.5px;
    text-transform: uppercase;
    letter-spacing: 0.3px;
    color: var(--text-mute);
    margin-bottom: 4px;
  }
  .hint {
    margin: 0;
    font-size: 11.5px;
    line-height: 1.4;
    color: var(--text-mute);
  }
  .hint code,
  .done code {
    font-family: var(--mono);
    color: var(--text-dim);
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
  .split {
    display: flex;
    gap: 10px;
  }
  .grow {
    flex: 1;
    min-width: 0;
  }
  input,
  select,
  textarea {
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
  textarea {
    height: auto;
    padding: 8px 10px;
    resize: vertical;
    font-family: var(--mono);
    font-size: 11px;
    line-height: 1.4;
  }
  input:focus,
  select:focus,
  textarea:focus {
    border-color: var(--accent);
  }
  .row {
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .msg {
    font-size: 11.5px;
    color: var(--err);
  }
  .msg.ok {
    color: var(--ok);
  }
  .done {
    font-size: 12px;
    line-height: 1.5;
    color: var(--text-dim);
    background: color-mix(in srgb, var(--ok) 12%, var(--bg));
    border: 1px solid color-mix(in srgb, var(--ok) 35%, transparent);
    border-radius: 7px;
    padding: 9px 11px;
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 8px;
  }
  .code-box {
    display: flex;
    flex-direction: column;
    gap: 6px;
    margin-top: 4px;
  }
  .err {
    font-size: 12px;
    color: var(--err);
    margin-bottom: 8px;
  }
  .danger-zone {
    margin: 4px 0 14px;
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
  .reset:disabled {
    opacity: 0.6;
    cursor: default;
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
  .actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
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
  .ghost.small {
    height: 27px;
    padding: 0 11px;
    font-size: 11.5px;
    align-self: flex-start;
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
  .primary:disabled,
  .ghost:disabled {
    opacity: 0.6;
    cursor: default;
  }
</style>
