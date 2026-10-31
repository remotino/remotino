<script lang="ts">
  import { onMount } from "svelte";
  import { Terminal } from "@xterm/xterm";
  import { FitAddon } from "@xterm/addon-fit";
  import "@xterm/xterm/css/xterm.css";
  import * as api from "$lib/api";
  import { ui } from "$lib/state.svelte";
  import { takeSsh } from "$lib/sshpending";

  // `active` tells us when this tab is the visible one; a terminal in a display:none pane
  // measures as 0x0, so we only (re)fit while active.
  let { id, active }: { id: string; active: boolean } = $props();

  let hostEl = $state<HTMLDivElement>();
  let term: Terminal | undefined;
  let fit: FitAddon | undefined;
  let unlisteners: Array<() => void> = [];

  // Reconnect state. Only credential-linked sessions (reconnectId set) auto-reconnect;
  // manual ones would need the secret again, which we don't retain.
  let connHost = "";
  let connPort = 22;
  let reconnectId: string | undefined;
  let destroyed = false;
  let everConnected = false;
  let retries = 0;
  let reconnectTimer: ReturnType<typeof setTimeout> | undefined;

  function scheduleSshReconnect() {
    if (destroyed || !reconnectId) return;
    if (retries >= 6) {
      ui.setStatus(id, "error");
      return;
    }
    retries += 1;
    ui.setStatus(id, "connecting");
    clearTimeout(reconnectTimer);
    reconnectTimer = setTimeout(
      async () => {
        if (destroyed) return;
        try {
          await api.sshConnect({
            id,
            host: connHost,
            port: connPort,
            cols: term?.cols ?? 80,
            rows: term?.rows ?? 24,
            entryId: reconnectId,
          });
          everConnected = true;
          retries = 0;
          ui.setStatus(id, "connected");
          term?.write("\r\n\x1b[38;5;244m[reconnected]\x1b[0m\r\n");
          term?.focus();
        } catch {
          scheduleSshReconnect();
        }
      },
      Math.min(1000 * retries, 5000),
    );
  }

  // Pull the terminal palette from the app's own CSS variables so it tracks the theme.
  function themeFromTokens(): Record<string, string> {
    const s = getComputedStyle(document.documentElement);
    const v = (name: string, fallback: string) =>
      s.getPropertyValue(name).trim() || fallback;
    return {
      background: v("--bg-inset", "#0b0f14"),
      foreground: v("--text", "#e6e6e6"),
      cursor: v("--accent", "#3ddc84"),
      selectionBackground: v("--sel", "#264f78"),
    };
  }

  onMount(() => {
    const creds = takeSsh(id);
    connHost = creds?.host ?? "";
    connPort = creds?.port ?? 22;
    reconnectId = creds?.entryId; // only credential-linked sessions can reconnect
    const s = getComputedStyle(document.documentElement);

    term = new Terminal({
      fontFamily: s.getPropertyValue("--mono").trim() || "monospace",
      fontSize: 13,
      cursorBlink: true,
      theme: themeFromTokens(),
      allowProposedApi: true,
    });
    fit = new FitAddon();
    term.loadAddon(fit);
    term.open(hostEl!);
    try {
      fit.fit();
    } catch {
      /* container not laid out yet; the active-effect will refit */
    }

    // Keystrokes -> remote shell.
    term.onData((d) => {
      void api.sshSend(id, new TextEncoder().encode(d));
    });

    // Refit when the container itself changes size (window resize, split changes).
    const ro = new ResizeObserver(() => {
      if (!active || !fit || !term) return;
      try {
        fit.fit();
        void api.sshResize(id, term.cols, term.rows);
      } catch {
        /* mid-teardown */
      }
    });
    if (hostEl) ro.observe(hostEl);

    (async () => {
      unlisteners.push(await api.onSshData(id, (bytes) => term?.write(bytes)));
      unlisteners.push(
        await api.onSshClosed(id, () => {
          // An established session that dropped: try to reconnect (credential-linked only).
          if (everConnected && !destroyed && reconnectId) {
            term?.write("\r\n\x1b[38;5;244m[connection lost — reconnecting…]\x1b[0m\r\n");
            scheduleSshReconnect();
          } else {
            ui.setStatus(id, "error");
            term?.write("\r\n\x1b[38;5;244m[session closed]\x1b[0m\r\n");
          }
        }),
      );

      if (!creds) {
        term?.write("\r\n\x1b[31mNo credentials for this session.\x1b[0m\r\n");
        ui.setStatus(id, "error");
        return;
      }
      try {
        await api.sshConnect({
          id,
          host: creds.host,
          port: creds.port,
          cols: term?.cols ?? 80,
          rows: term?.rows ?? 24,
          // Auto-fill resolves the credential backend-side; manual passes user/pass.
          ...(creds.entryId
            ? { entryId: creds.entryId }
            : { username: creds.username, password: creds.password }),
        });
        everConnected = true;
        retries = 0;
        ui.setStatus(id, "connected");
        term?.focus();
      } catch (e) {
        term?.write(`\r\n\x1b[31m${String(e)}\x1b[0m\r\n`);
        ui.setStatus(id, "error");
      }
    })();

    return () => {
      destroyed = true; // stop any reconnect attempts
      clearTimeout(reconnectTimer);
      ro.disconnect();
      void api.sshClose(id);
      for (const u of unlisteners) u();
      term?.dispose();
      term = undefined;
    };
  });

  // Becoming active: the pane was display:none, so refit to the now-real size and tell the
  // remote. Also re-apply the theme in case it changed while hidden.
  $effect(() => {
    if (active && fit && term) {
      term.options.theme = themeFromTokens();
      queueMicrotask(() => {
        try {
          fit!.fit();
          void api.sshResize(id, term!.cols, term!.rows);
          term!.focus();
        } catch {
          /* not laid out */
        }
      });
    }
  });

  // Follow the app theme toggle live.
  $effect(() => {
    void ui.theme;
    if (term) term.options.theme = themeFromTokens();
  });
</script>

<div class="term" bind:this={hostEl}></div>

<style>
  .term {
    height: 100%;
    width: 100%;
    background: var(--bg-inset);
    padding: 6px 8px;
    box-sizing: border-box;
  }
  /* xterm's viewport scrollbar, toned to the app. */
  .term :global(.xterm-viewport) {
    scrollbar-width: thin;
  }
</style>
