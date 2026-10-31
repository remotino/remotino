<script lang="ts">
  import { tree, type Connection } from "$lib/tree.svelte";
  import { ui } from "$lib/state.svelte";

  let query = $state("");
  let cursor = $state(0);
  let inputEl = $state<HTMLInputElement | null>(null);

  // At 100+ entries this is the primary navigation, so the match has to feel instant. A
  // plain substring rank is enough and predictable; fuzzy scoring can come later.
  const results = $derived.by((): Connection[] => {
    const q = query.trim().toLowerCase();
    const all = tree.allConnections;
    if (!q) return all.slice(0, 50);
    return all
      .filter((c) => c.name.toLowerCase().includes(q) || c.host.toLowerCase().includes(q))
      .slice(0, 50);
  });

  $effect(() => {
    // Refocus and reset each time the palette opens.
    if (ui.paletteOpen) {
      query = "";
      cursor = 0;
      queueMicrotask(() => inputEl?.focus());
    }
  });

  // Keep the cursor in range as results shrink.
  $effect(() => {
    if (cursor >= results.length) cursor = Math.max(0, results.length - 1);
  });

  function open(c: Connection) {
    ui.paletteOpen = false;
    ui.requestConnect(c);
  }

  function onKey(e: KeyboardEvent) {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      cursor = Math.min(cursor + 1, results.length - 1);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      cursor = Math.max(cursor - 1, 0);
    } else if (e.key === "Enter") {
      e.preventDefault();
      const c = results[cursor];
      if (c) open(c);
    } else if (e.key === "Escape") {
      ui.paletteOpen = false;
    }
  }
</script>

{#if ui.paletteOpen}
  <button
    class="overlay"
    onclick={() => (ui.paletteOpen = false)}
    aria-label="Close palette"
  ></button>
  <div class="palette" role="dialog" aria-label="Command palette">
    <div class="input-row">
      <span class="prompt">›</span>
      <!-- svelte-ignore a11y_autofocus -->
      <input
        bind:this={inputEl}
        bind:value={query}
        onkeydown={onKey}
        placeholder="Jump to a connection…"
        spellcheck="false"
        autofocus
      />
      <span class="count">{results.length}</span>
    </div>

    <div class="list">
      {#each results as c, i (c.id)}
        <button
          class="res"
          class:active={i === cursor}
          onmouseenter={() => (cursor = i)}
          onclick={() => open(c)}
        >
          <span class="badge {c.kind}">{c.kind.toUpperCase()}</span>
          <span class="name">{c.name}</span>
          <span class="path">{tree.folderName(c.folder)}</span>
          <span class="spacer"></span>
          <span class="host">{c.host}<span class="port">:{c.port}</span></span>
        </button>
      {/each}
      {#if results.length === 0}
        <div class="none">No matches. Try fewer characters.</div>
      {/if}
    </div>

    <div class="foot">
      <span><b>↑↓</b> navigate</span>
      <span><b>↵</b> open session</span>
      <span><b>esc</b> close</span>
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
  .palette {
    position: fixed;
    z-index: 71;
    top: 11vh;
    left: 50%;
    transform: translateX(-50%);
    width: min(660px, 92%);
    background: var(--bg-2);
    border: 1px solid var(--border-2);
    border-radius: 10px;
    box-shadow: 0 24px 60px rgba(0, 0, 0, 0.5);
    overflow: hidden;
    animation: rt-pop 0.12s;
  }
  .input-row {
    display: flex;
    align-items: center;
    gap: 9px;
    padding: 12px 15px;
    border-bottom: 1px solid var(--border);
  }
  .prompt {
    font-family: var(--mono);
    color: var(--accent);
    font-size: 16px;
    font-weight: 700;
  }
  .input-row input {
    flex: 1;
    background: transparent;
    border: 0;
    outline: none;
    font-size: 16px;
    font-family: var(--mono);
  }
  .input-row .count {
    font-family: var(--mono);
    font-size: 11px;
    color: var(--text-mute);
  }
  .list {
    max-height: 46vh;
    overflow: auto;
  }
  .res {
    display: flex;
    align-items: center;
    gap: 9px;
    width: 100%;
    height: 38px;
    padding: 0 15px;
    background: transparent;
    border: 0;
    cursor: pointer;
    text-align: left;
    color: var(--text);
  }
  .res.active {
    background: var(--sel);
    box-shadow: inset 3px 0 0 var(--accent);
  }
  .badge {
    flex: 0 0 auto;
    width: 29px;
    text-align: center;
    font-family: var(--mono);
    font-size: 9px;
    font-weight: 700;
    padding: 1px 0;
    border-radius: 2px;
  }
  .badge.ssh {
    color: var(--ssh);
    background: color-mix(in srgb, var(--ssh) 15%, transparent);
  }
  .badge.rdp {
    color: var(--rdp);
    background: color-mix(in srgb, var(--rdp) 15%, transparent);
  }
  .name {
    font-size: 13.5px;
  }
  .path {
    font-family: var(--mono);
    font-size: 11px;
    color: var(--text-mute);
  }
  .spacer {
    flex: 1;
  }
  .host {
    font-family: var(--mono);
    font-size: 12px;
    color: var(--text-dim);
  }
  .port {
    color: var(--text-mute);
  }
  .none {
    padding: 26px;
    text-align: center;
    color: var(--text-mute);
    font-size: 12.5px;
  }
  .foot {
    display: flex;
    gap: 14px;
    padding: 8px 15px;
    border-top: 1px solid var(--border);
    font-family: var(--mono);
    font-size: 11px;
    color: var(--text-mute);
  }
  .foot b {
    color: var(--text-dim);
  }
</style>
