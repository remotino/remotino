<script lang="ts">
  import { onMount } from "svelte";
  import { fade } from "svelte/transition";
  import * as api from "$lib/api";
  import { ui } from "$lib/state.svelte";
  import { takeSsh } from "$lib/sshpending";
  import { SCANCODES } from "$lib/scancodes";

  // `active` gates focus/pointer capture the way it does for the terminal.
  let { id, active }: { id: string; active: boolean } = $props();

  let wrapEl = $state<HTMLDivElement>();
  let canvasEl = $state<HTMLCanvasElement>();
  let ctx: CanvasRenderingContext2D | null = null;
  // Reactive so the status bar reflects the live desktop resolution across dynamic resizes.
  let deskW = $state(0);
  let deskH = $state(0);
  let connHost = $state("");
  // True when the session was refused because the server key changed (possible MITM).
  let mismatch = $state(false);

  // Resolution badge: flashes briefly only when the desktop *resizes*, then fades. Not shown
  // on the initial connect size, and not left permanently on screen.
  let showBadge = $state(false);
  let sizeSeen = false;
  let badgeTimer: ReturnType<typeof setTimeout> | undefined;
  function flashBadge() {
    showBadge = true;
    clearTimeout(badgeTimer);
    badgeTimer = setTimeout(() => (showBadge = false), 2500);
  }

  // Reconnect state. We only auto-reconnect credential-linked sessions (reconnectId set) -
  // manual ones would need the secret again, which we deliberately don't retain.
  let connPort = 3389;
  let reconnectId: string | undefined;
  let destroyed = false;
  let everConnected = false;
  let gracefulClose = false;
  let retries = 0;
  let reconnectTimer: ReturnType<typeof setTimeout> | undefined;

  // Map a pointer event to remote desktop pixels (canvas is stretched to the wrapper).
  function mapPos(e: MouseEvent): { x: number; y: number } {
    const r = canvasEl!.getBoundingClientRect();
    const x = ((e.clientX - r.left) / r.width) * deskW;
    const y = ((e.clientY - r.top) / r.height) * deskH;
    return {
      x: Math.max(0, Math.min(deskW - 1, Math.round(x))),
      y: Math.max(0, Math.min(deskH - 1, Math.round(y))),
    };
  }

  function onFrame(buf: ArrayBuffer) {
    const view = new DataView(buf);
    const kind = view.getUint8(0);
    if (kind === 1) {
      // FRAME: [u8 kind][u16 x,y,w,h][rgba…]
      const x = view.getUint16(1);
      const y = view.getUint16(3);
      const w = view.getUint16(5);
      const h = view.getUint16(7);
      const rgba = new Uint8ClampedArray(buf, 9, w * h * 4);
      // Copy: ImageData needs its own buffer, and `buf` is transient.
      const img = new ImageData(new Uint8ClampedArray(rgba), w, h);
      ctx?.putImageData(img, x, y);
    } else if (kind === 2) {
      // SIZE: [u8 kind][u16 w,h]
      deskW = view.getUint16(1);
      deskH = view.getUint16(3);
      if (canvasEl) {
        canvasEl.width = deskW;
        canvasEl.height = deskH;
        ctx = canvasEl.getContext("2d");
      }
      // Flash the badge on a real resize (a new SIZE after the first), never on connect.
      if (sizeSeen) flashBadge();
      sizeSeen = true;
    } else if (kind === 3) {
      // STATUS: [u8 kind][utf-8]
      const text = new TextDecoder().decode(new Uint8Array(buf, 1));
      if (text === "connected") {
        everConnected = true;
        gracefulClose = false;
        retries = 0;
        ui.setStatus(id, "connected");
      } else if (text.startsWith("certmismatch:")) {
        mismatch = true;
        ui.setStatus(id, "error");
      } else if (text === "closed") {
        gracefulClose = true; // the remote ended it on purpose; don't auto-reconnect
        ui.setStatus(id, "error");
      } else if (text === "ended") {
        // The sidecar went away. Reconnect if this was an established session that dropped.
        if (everConnected && !destroyed && !mismatch && !gracefulClose && reconnectId) {
          scheduleReconnect();
        } else if (!destroyed) {
          ui.setStatus(id, "error");
        }
      } else if (text.startsWith("error")) ui.setStatus(id, "error");
    } else if (kind === 4) {
      // CURSOR: [u8 kind][u16 hx][u16 hy][u16 w][u16 h][rgba]
      const hx = view.getUint16(1);
      const hy = view.getUint16(3);
      const w = view.getUint16(5);
      const h = view.getUint16(7);
      if (w > 0 && h > 0) applyCursor(hx, hy, w, h, new Uint8ClampedArray(buf, 9, w * h * 4));
    } else if (kind === 5) {
      if (canvasEl) canvasEl.style.cursor = "none";
    } else if (kind === 6) {
      if (canvasEl) canvasEl.style.cursor = "default";
    }
  }

  // Turn a remote cursor bitmap into a CSS cursor on the canvas.
  let cursorCanvas: HTMLCanvasElement | undefined;
  function applyCursor(hx: number, hy: number, w: number, h: number, rgba: Uint8ClampedArray) {
    if (!canvasEl) return;
    cursorCanvas ??= document.createElement("canvas");
    cursorCanvas.width = w;
    cursorCanvas.height = h;
    const cctx = cursorCanvas.getContext("2d");
    if (!cctx) return;
    cctx.putImageData(new ImageData(new Uint8ClampedArray(rgba), w, h), 0, 0);
    // Browsers cap the hotspot at the image bounds.
    const cx = Math.min(hx, w - 1);
    const cy = Math.min(hy, h - 1);
    canvasEl.style.cursor = `url(${cursorCanvas.toDataURL("image/png")}) ${cx} ${cy}, auto`;
  }

  // Scancodes currently held down, so we can release them if focus leaves. Without this a
  // modifier whose keyup never arrives (pressing Win opens the local Start menu and steals
  // focus; Alt+Tab switches away) stays "stuck down" on the remote - e.g. Ctrl+V then acts
  // as Win+Ctrl+V. Keyed by e.code so a repeat keydown doesn't add duplicates.
  const pressed = new Map<string, { code: number; extended: boolean }>();

  function sendKey(e: KeyboardEvent, down: boolean) {
    const scan = SCANCODES[e.code];
    if (!scan) return;
    e.preventDefault();
    if (down) pressed.set(e.code, { code: scan[0], extended: scan[1] });
    else pressed.delete(e.code);
    void api.rdpInput(id, { t: "key", code: scan[0], down, extended: scan[1] });
  }

  // Release every key we think is held. Called whenever focus leaves the canvas, so no
  // modifier can be left stuck on the remote.
  function releaseAllKeys() {
    for (const k of pressed.values()) {
      void api.rdpInput(id, { t: "key", code: k.code, down: false, extended: k.extended });
    }
    pressed.clear();
  }

  // Ctrl+Alt+Del can't arrive as a keydown (the OS intercepts it), so it needs a button.
  function sendCtrlAltDel() {
    const seq = [
      { code: 0x1d, ext: false }, // LeftCtrl
      { code: 0x38, ext: false }, // LeftAlt
      { code: 0x53, ext: true }, // Delete (extended)
    ];
    for (const k of seq) void api.rdpInput(id, { t: "key", code: k.code, down: true, extended: k.ext });
    for (const k of [...seq].reverse()) void api.rdpInput(id, { t: "key", code: k.code, down: false, extended: k.ext });
    canvasEl?.focus();
  }

  // Clearing the pin and closing the tab; reopening the connection re-pins on first use.
  async function retrust() {
    if (connHost) await api.forgetHostKey(connHost);
    void api.rdpClose(id);
    ui.closeSession(id);
  }

  // (Re)connect with the given auth, sizing the desktop to the current pane.
  function connectWith(auth: Record<string, unknown>) {
    const dpr = window.devicePixelRatio || 1;
    const w = Math.max(640, Math.round((wrapEl?.clientWidth ?? 1280) * dpr));
    const h = Math.max(480, Math.round((wrapEl?.clientHeight ?? 800) * dpr));
    deskW = w;
    deskH = h;
    if (canvasEl) {
      canvasEl.width = w;
      canvasEl.height = h;
    }
    return api.rdpConnect({ id, host: connHost, port: connPort, width: w, height: h, ...auth }, onFrame);
  }

  function scheduleReconnect() {
    if (destroyed || mismatch || !reconnectId) return;
    if (retries >= 6) {
      ui.setStatus(id, "error");
      return;
    }
    retries += 1;
    ui.setStatus(id, "connecting");
    clearTimeout(reconnectTimer);
    reconnectTimer = setTimeout(
      () => {
        if (destroyed) return;
        void connectWith({ entryId: reconnectId }).catch(() => scheduleReconnect());
      },
      Math.min(1000 * retries, 5000),
    );
  }

  onMount(() => {
    const creds = takeSsh(id);
    connHost = creds?.host ?? "";
    connPort = creds?.port ?? 3389;
    reconnectId = creds?.entryId; // only credential-linked sessions can reconnect
    ctx = canvasEl?.getContext("2d") ?? null;

    if (!creds) {
      ui.setStatus(id, "error");
      return;
    }

    const auth = creds.entryId
      ? { entryId: creds.entryId }
      : { username: creds.username, password: creds.password };
    void connectWith(auth).catch(() => ui.setStatus(id, "error"));

    // Focus so keyboard events land here.
    queueMicrotask(() => canvasEl?.focus());

    // Ask the remote to match our pane size (debounced). The server answers with a
    // reactivation; the sidecar then sends a new SIZE and the canvas follows.
    //
    // Only while this tab is visible: an inactive pane is display:none, which the observer
    // sees as a 0x0 resize. Acting on that would drop the desktop to the minimum size and
    // re-render it on every tab switch (the flash back to full res). We ignore those.
    let resizeTimer: ReturnType<typeof setTimeout> | undefined;
    let lastReq = `${deskW}x${deskH}`;
    const ro = new ResizeObserver(() => {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(() => {
        const rawW = wrapEl?.clientWidth ?? 0;
        const rawH = wrapEl?.clientHeight ?? 0;
        if (!active || rawW === 0 || rawH === 0) return; // hidden / inactive pane
        const dpr = window.devicePixelRatio || 1;
        const nw = Math.max(640, Math.round(rawW * dpr));
        const nh = Math.max(480, Math.round(rawH * dpr));
        const key = `${nw}x${nh}`;
        if (key === lastReq) return;
        lastReq = key;
        void api.rdpInput(id, { t: "resize", w: nw, h: nh });
      }, 250);
    });
    if (wrapEl) ro.observe(wrapEl);

    // The window losing focus (Win key opened the Start menu, Alt+Tab, click elsewhere) or
    // the tab being hidden means no more keyups will arrive - release everything so nothing
    // sticks down on the remote.
    const onWindowBlur = () => releaseAllKeys();
    const onVisibility = () => {
      if (document.hidden) releaseAllKeys();
    };
    window.addEventListener("blur", onWindowBlur);
    document.addEventListener("visibilitychange", onVisibility);

    return () => {
      destroyed = true; // stop any reconnect attempts
      clearTimeout(resizeTimer);
      clearTimeout(reconnectTimer);
      clearTimeout(badgeTimer);
      ro.disconnect();
      window.removeEventListener("blur", onWindowBlur);
      document.removeEventListener("visibilitychange", onVisibility);
      void api.rdpClose(id);
    };
  });

  // Refocus when this tab becomes active; release keys when it goes inactive so a modifier
  // held during a tab switch doesn't stay down on the remote.
  $effect(() => {
    if (active) queueMicrotask(() => canvasEl?.focus());
    else releaseAllKeys();
  });
</script>

<div class="rdp" bind:this={wrapEl}>
  {#if mismatch}
    <div class="mitm">
      <div class="mitm-title">⚠ Server key changed</div>
      <p>
        The identity key for <b>{connHost}</b> is different from the one you first trusted.
        This can mean the host was rebuilt — or a machine-in-the-middle. Only continue if you
        know why it changed.
      </p>
      <button class="mitm-btn" onclick={retrust}>Trust the new key & close</button>
    </div>
  {/if}
  <button class="cad" onclick={sendCtrlAltDel} title="Send Ctrl+Alt+Del to the remote">
    Ctrl+Alt+Del
  </button>
  <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
  <canvas
    bind:this={canvasEl}
    tabindex="0"
    onpointermove={(e) => {
      const p = mapPos(e);
      void api.rdpInput(id, { t: "m_move", x: p.x, y: p.y });
    }}
    onpointerdown={(e) => {
      canvasEl?.focus();
      const p = mapPos(e);
      const button = e.button === 2 ? "right" : e.button === 1 ? "middle" : "left";
      void api.rdpInput(id, { t: "m_btn", x: p.x, y: p.y, button, down: true });
    }}
    onpointerup={(e) => {
      const p = mapPos(e);
      const button = e.button === 2 ? "right" : e.button === 1 ? "middle" : "left";
      void api.rdpInput(id, { t: "m_btn", x: p.x, y: p.y, button, down: false });
    }}
    onwheel={(e) => {
      e.preventDefault();
      const p = mapPos(e);
      void api.rdpInput(id, { t: "m_wheel", x: p.x, y: p.y, delta: e.deltaY < 0 ? 120 : -120 });
    }}
    oncontextmenu={(e) => e.preventDefault()}
    onkeydown={(e) => sendKey(e, true)}
    onkeyup={(e) => sendKey(e, false)}
    onblur={releaseAllKeys}
  ></canvas>
  {#if showBadge && connHost && deskW > 0 && deskH > 0}
    <div class="statusbar" aria-hidden="true" transition:fade={{ duration: 200 }}>{connHost} · {deskW}×{deskH}</div>
  {/if}
</div>

<style>
  .rdp {
    height: 100%;
    width: 100%;
    background: #000;
    display: flex;
    overflow: hidden;
    position: relative;
  }
  /* Subtle overlay control; the browser can't capture Ctrl+Alt+Del itself. */
  .cad {
    position: absolute;
    top: 8px;
    right: 10px;
    z-index: 5;
    font-family: var(--mono);
    font-size: 11px;
    color: var(--text-dim);
    background: color-mix(in srgb, var(--bg-2) 85%, transparent);
    border: 1px solid var(--border-2);
    border-radius: 6px;
    padding: 4px 8px;
    cursor: pointer;
    opacity: 0.35;
    transition: opacity 0.12s;
  }
  .cad:hover {
    opacity: 1;
    color: var(--text);
  }
  .mitm {
    position: absolute;
    z-index: 6;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    width: min(420px, 90%);
    background: var(--bg-2);
    border: 1px solid var(--err);
    border-radius: 11px;
    padding: 18px;
    box-shadow: 0 24px 60px rgba(0, 0, 0, 0.6);
  }
  .mitm-title {
    font-size: 14px;
    font-weight: 600;
    color: var(--err);
    margin-bottom: 8px;
  }
  .mitm p {
    margin: 0 0 14px;
    font-size: 12.5px;
    line-height: 1.5;
    color: var(--text-dim);
  }
  .mitm-btn {
    height: 32px;
    padding: 0 14px;
    background: transparent;
    border: 1px solid var(--err);
    border-radius: 7px;
    color: var(--err);
    cursor: pointer;
    font-size: 12.5px;
  }
  .mitm-btn:hover {
    background: color-mix(in srgb, var(--err) 15%, transparent);
  }
  canvas {
    width: 100%;
    height: 100%;
    display: block;
    outline: none;
    /* Crisp scaling of the remote framebuffer. */
    image-rendering: pixelated;
    cursor: default;
    touch-action: none;
  }
  /* Host + live desktop resolution. Flashed only during a resize, then faded out, so it never
     permanently covers the remote's own taskbar in this corner. pointer-events:none so it can
     never eat a click near the desktop corner. */
  .statusbar {
    position: absolute;
    right: 10px;
    bottom: 8px;
    z-index: 5;
    font-family: var(--mono);
    font-size: 11px;
    letter-spacing: 0.2px;
    color: var(--accent);
    background: #000;
    border: 1px solid color-mix(in srgb, var(--accent) 40%, transparent);
    border-radius: 6px;
    padding: 4px 8px;
    pointer-events: none;
  }
</style>
