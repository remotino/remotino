<script lang="ts">
  import { ui } from "$lib/state.svelte";
  import * as api from "$lib/api";
  import Connections from "./Connections.svelte";
  import Palette from "./Palette.svelte";
  import Terminal from "./Terminal.svelte";
  import RdpCanvas from "./RdpCanvas.svelte";
  import SshAuth from "./SshAuth.svelte";
  import SettingsModal from "./SettingsModal.svelte";
  import UsersModal from "./UsersModal.svelte";
  import AuditModal from "./AuditModal.svelte";

  let settingsOpen = $state(false);
  let usersOpen = $state(false);
  let auditOpen = $state(false);

  async function doLock() {
    await api.lock();
    ui.sessions = [];
    ui.activeTab = 0;
    ui.screen = "unlock";
  }

  // Global keys: Cmd/Ctrl+K opens the palette. Registered at the shell so it works from
  // any tab.
  function onKeydown(e: KeyboardEvent) {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
      e.preventDefault();
      ui.paletteOpen = !ui.paletteOpen;
    }
  }
</script>

<svelte:window onkeydown={onKeydown} />

<div class="shell">
  <div class="tabs">
    <!-- Tab 0: Connections. Never closable. -->
    <button
      class="tab"
      class:active={ui.activeTab === 0}
      onclick={() => (ui.activeTab = 0)}
    >
      <span class="dot connections"></span>
      Connections
    </button>

    {#each ui.sessions as s, i (s.id)}
      <button
        class="tab"
        class:active={ui.activeTab === i + 1}
        onclick={() => (ui.activeTab = i + 1)}
      >
        <span class="dot {s.status}"></span>
        <span class="tab-badge {s.kind}">{s.kind.toUpperCase()}</span>
        {s.name}
        <span
          class="close"
          role="button"
          tabindex="0"
          onclick={(e) => {
            e.stopPropagation();
            ui.closeSession(s.id);
          }}
          onkeydown={(e) => {
            if (e.key === "Enter") {
              e.stopPropagation();
              ui.closeSession(s.id);
            }
          }}
        >×</span>
      </button>
    {/each}

    <div class="spacer"></div>
    <button class="icon" title="Toggle theme" aria-label="Toggle theme" onclick={() => ui.toggleTheme()}>
      {#if ui.theme === "dark"}
        <!-- sun -->
        <svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true">
          <circle cx="8" cy="8" r="3" fill="none" stroke="currentColor" stroke-width="1.4" />
          <g stroke="currentColor" stroke-width="1.4" stroke-linecap="round">
            <path d="M8 1.5v1.6M8 12.9v1.6M1.5 8h1.6M12.9 8h1.6M3.4 3.4l1.1 1.1M11.5 11.5l1.1 1.1M12.6 3.4l-1.1 1.1M4.5 11.5l-1.1 1.1" />
          </g>
        </svg>
      {:else}
        <!-- moon -->
        <svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true">
          <path d="M13 9.5A5.5 5.5 0 0 1 6.5 3a5.5 5.5 0 1 0 6.5 6.5z" fill="currentColor" />
        </svg>
      {/if}
    </button>
    <button class="icon" title="Users & sharing" aria-label="Users" onclick={() => (usersOpen = true)}>
      <svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true">
        <circle cx="6" cy="6" r="2.4" fill="none" stroke="currentColor" stroke-width="1.3" />
        <path d="M2.2 13c0-2.1 1.7-3.4 3.8-3.4S9.8 10.9 9.8 13" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" />
        <path d="M10.5 4.2a2.2 2.2 0 0 1 0 4M11.2 9.7c1.7.2 3 1.4 3 3.3" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" />
      </svg>
    </button>
    <button class="icon" title="Audit log" aria-label="Audit log" onclick={() => (auditOpen = true)}>
      <svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true">
        <path d="M4 2.2h6l2.4 2.4v9.2H4z" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linejoin="round" />
        <path d="M6 7.4h4M6 9.8h4M6 5h2" fill="none" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" />
      </svg>
    </button>
    <button class="icon" title="Settings" aria-label="Settings" onclick={() => (settingsOpen = true)}>
      <!-- gear -->
      <svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true">
        <circle cx="8" cy="8" r="2.1" fill="none" stroke="currentColor" stroke-width="1.4" />
        <path
          d="M8 1.6l.9 1.6a5.5 5.5 0 0 1 1.5.6l1.8-.4 1 1.7-1.2 1.4c.1.5.1 1 0 1.5l1.2 1.4-1 1.7-1.8-.4a5.5 5.5 0 0 1-1.5.9L8 14.4l-.9-1.9a5.5 5.5 0 0 1-1.5-.9l-1.8.4-1-1.7 1.2-1.4a5.5 5.5 0 0 1 0-1.5L2 5.1l1-1.7 1.8.4a5.5 5.5 0 0 1 1.5-.6z"
          fill="none"
          stroke="currentColor"
          stroke-width="1.2"
          stroke-linejoin="round"
        />
      </svg>
    </button>
    <button class="icon" title="Lock" aria-label="Lock" onclick={doLock}>
      <!-- power / lock-out -->
      <svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true">
        <path d="M8 2v6" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" />
        <path d="M5 4.2a5 5 0 1 0 6 0" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" />
      </svg>
    </button>
  </div>

  {#if ui.sqlWarning}
    <div class="sql-warn" role="alert">
      <svg viewBox="0 0 16 16" width="15" height="15" aria-hidden="true">
        <path d="M8 1.7 15 14H1z" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round" />
        <path d="M8 6.4v3.2" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" />
        <circle cx="8" cy="11.6" r="0.8" fill="currentColor" />
      </svg>
      <span class="sql-warn-text">{ui.sqlWarning}</span>
      <button class="sql-warn-x" aria-label="Dismiss" onclick={() => (ui.sqlWarning = null)}>×</button>
    </div>
  {/if}

  <div class="body">
    <!-- All panes stay mounted; only the active one is shown. A live SSH session must not
         be torn down just because the user glanced at another tab. -->
    <div class="pane" class:hidden={ui.activeTab !== 0}>
      <Connections />
    </div>

    {#each ui.sessions as s, i (s.id)}
      <div class="pane" class:hidden={ui.activeTab !== i + 1}>
        {#if s.kind === "ssh"}
          <Terminal id={s.id} active={ui.activeTab === i + 1} />
        {:else}
          <RdpCanvas id={s.id} active={ui.activeTab === i + 1} />
        {/if}
      </div>
    {/each}
  </div>
</div>

<Palette />
<SshAuth />
<SettingsModal bind:open={settingsOpen} />
<UsersModal bind:open={usersOpen} />
<AuditModal bind:open={auditOpen} />

<style>
  .shell {
    height: 100%;
    display: flex;
    flex-direction: column;
  }
  .tabs {
    flex: 0 0 auto;
    height: 28px;
    display: flex;
    align-items: stretch;
    background: var(--bg-inset);
    border-bottom: 1px solid var(--border);
    padding: 0 4px;
    gap: 1px;
  }
  .tab {
    display: flex;
    align-items: center;
    gap: 6px;
    height: 28px;
    padding: 0 11px;
    background: transparent;
    border: 0;
    border-top: 2px solid transparent;
    color: var(--text-dim);
    font-size: 12px;
    cursor: pointer;
    white-space: nowrap;
  }
  .tab:hover {
    color: var(--text);
    background: var(--bg-2);
  }
  .tab.active {
    color: var(--text);
    background: var(--bg);
    border-top-color: var(--accent);
  }
  .dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    flex: 0 0 auto;
  }
  .dot.connections {
    background: var(--text-mute);
  }
  .dot.connected {
    background: var(--ok);
  }
  .dot.connecting {
    background: var(--warn);
    animation: rt-pulse 1s infinite;
  }
  .dot.error {
    background: var(--err);
  }
  .tab-badge {
    font-family: var(--mono);
    font-size: 8.5px;
    font-weight: 700;
    padding: 1px 3px;
    border-radius: 2px;
  }
  .tab-badge.ssh {
    color: var(--ssh);
    background: color-mix(in srgb, var(--ssh) 15%, transparent);
  }
  .tab-badge.rdp {
    color: var(--rdp);
    background: color-mix(in srgb, var(--rdp) 15%, transparent);
  }
  .close {
    margin-left: 4px;
    color: var(--text-mute);
    font-size: 14px;
    line-height: 1;
    border-radius: 3px;
    padding: 0 2px;
  }
  .close:hover {
    color: var(--text);
    background: var(--bg-3);
  }
  .spacer {
    flex: 1;
  }
  .icon {
    width: 28px;
    background: transparent;
    border: 0;
    color: var(--text-mute);
    cursor: pointer;
    font-size: 13px;
  }
  .icon:hover {
    color: var(--text);
  }
  .sql-warn {
    flex: 0 0 auto;
    display: flex;
    align-items: center;
    gap: 9px;
    padding: 8px 12px;
    background: color-mix(in srgb, var(--warn) 16%, var(--bg));
    border-bottom: 1px solid color-mix(in srgb, var(--warn) 45%, transparent);
    color: var(--warn);
  }
  .sql-warn-text {
    flex: 1;
    font-size: 12px;
    line-height: 1.4;
    color: var(--text);
  }
  .sql-warn-x {
    flex: 0 0 auto;
    background: transparent;
    border: 0;
    color: var(--text-mute);
    font-size: 17px;
    line-height: 1;
    cursor: pointer;
    padding: 0 4px;
  }
  .sql-warn-x:hover {
    color: var(--text);
  }
  .body {
    flex: 1;
    min-height: 0;
    position: relative;
  }
  .pane {
    position: absolute;
    inset: 0;
  }
  .pane.hidden {
    display: none;
  }
  .session {
    height: 100%;
    background: var(--bg-inset);
    background-image: radial-gradient(var(--border) 0.5px, transparent 0.5px);
    background-size: 22px 22px;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .session-center {
    text-align: center;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 8px;
    opacity: 0.7;
  }
  .badge {
    width: 34px;
    text-align: center;
    font-family: var(--mono);
    font-size: 10px;
    font-weight: 700;
    padding: 2px 0;
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
  .s-name {
    font-size: 15px;
    color: var(--text);
  }
  .s-status {
    font-family: var(--mono);
    font-size: 12px;
    color: var(--text-mute);
  }
</style>
