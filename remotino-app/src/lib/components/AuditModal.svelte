<script lang="ts">
  import * as api from "$lib/api";

  let { open = $bindable(false) }: { open?: boolean } = $props();

  let log = $state<api.AuditLog | null>(null);
  let loading = $state(false);
  let error = $state("");
  let filter = $state("");

  $effect(() => {
    if (open) {
      error = "";
      filter = "";
      loading = true;
      api
        .auditLog()
        .then((l) => (log = l))
        .catch((e) => (error = String(e)))
        .finally(() => (loading = false));
    }
  });

  const rows = $derived.by(() => {
    const q = filter.trim().toLowerCase();
    const all = log?.entries ?? [];
    if (!q) return all;
    return all.filter(
      (e) =>
        e.actor.toLowerCase().includes(q) ||
        e.summary.toLowerCase().includes(q) ||
        e.action.toLowerCase().includes(q),
    );
  });

  function when(ts: string): string {
    const d = new Date(ts);
    if (isNaN(d.getTime())) return ts;
    return d.toLocaleString(undefined, {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
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
  <div class="modal" role="dialog" aria-label="Audit log" tabindex="-1" onkeydown={onKey}>
    <div class="head">
      <div>
        <div class="title">Audit log</div>
        <p class="sub">Every change to this repository, signed and in order. Read-only.</p>
      </div>
      {#if log}
        <div class="chain" class:bad={!log.intact} title="Each entry is signed and links to the previous one's hash. A deleted or edited row breaks the chain.">
          {#if log.intact}
            <svg viewBox="0 0 16 16" width="13" height="13" aria-hidden="true"><path d="M3 8.5 6.5 12 13 4.5" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>
            Chain intact · {log.count} events
          {:else}
            <svg viewBox="0 0 16 16" width="13" height="13" aria-hidden="true"><path d="M8 2 15 14H1z" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/><path d="M8 6.4v3.4M8 11.6v.01" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>
            Tampering detected at #{log.brokenAt}
          {/if}
        </div>
      {/if}
    </div>

    <div class="search">
      <input bind:value={filter} placeholder="Filter by user or action…" spellcheck="false" />
    </div>

    <div class="table">
      <div class="tr th">
        <span class="c-when">When</span>
        <span class="c-who">Who</span>
        <span class="c-what">Action</span>
        <span class="c-seq">#</span>
      </div>
      {#if loading}
        <div class="empty">Loading…</div>
      {:else if error}
        <div class="empty err">{error}</div>
      {:else if rows.length === 0}
        <div class="empty">{filter ? "No matching activity." : "No activity yet."}</div>
      {:else}
        {#each rows as e (e.seq)}
          <div class="tr">
            <span class="c-when">{when(e.timestamp)}</span>
            <span class="c-who">
              <span class="who-name" class:you={e.actor === "You"}>{e.actor}</span>
              <span class="who-fp">{e.actorFingerprint}</span>
            </span>
            <span class="c-what">{e.summary}</span>
            <span class="c-seq">{e.seq}</span>
          </div>
        {/each}
      {/if}
    </div>

    <div class="actions">
      <button class="ghost" onclick={close}>Close</button>
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
    top: 8vh;
    left: 50%;
    transform: translateX(-50%);
    width: min(680px, 94%);
    max-height: 84vh;
    display: flex;
    flex-direction: column;
    background: var(--bg-2);
    border: 1px solid var(--border-2);
    border-radius: 11px;
    box-shadow: 0 24px 60px rgba(0, 0, 0, 0.5);
    padding: 16px;
    animation: rt-pop 0.12s;
  }
  .head {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 14px;
  }
  .title {
    font-size: 14px;
    font-weight: 600;
  }
  .sub {
    margin: 4px 0 0;
    font-size: 12px;
    color: var(--text-dim);
  }
  .chain {
    flex: 0 0 auto;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: 11.5px;
    font-family: var(--mono);
    color: var(--ok);
    background: color-mix(in srgb, var(--ok) 12%, transparent);
    border: 1px solid color-mix(in srgb, var(--ok) 35%, transparent);
    border-radius: 7px;
    padding: 5px 9px;
    white-space: nowrap;
  }
  .chain.bad {
    color: var(--err);
    background: color-mix(in srgb, var(--err) 12%, transparent);
    border-color: color-mix(in srgb, var(--err) 40%, transparent);
  }
  .search {
    margin: 14px 0 8px;
  }
  .search input {
    width: 100%;
    height: 30px;
    padding: 0 11px;
    background: var(--bg);
    border: 1px solid var(--border-2);
    border-radius: 7px;
    outline: none;
    color: var(--text);
    font-size: 12.5px;
    box-sizing: border-box;
  }
  .search input:focus {
    border-color: var(--accent);
  }
  .table {
    flex: 1;
    overflow: auto;
    border: 1px solid var(--border);
    border-radius: 8px;
  }
  .tr {
    display: grid;
    grid-template-columns: 120px 1.2fr 1.6fr 44px;
    gap: 10px;
    align-items: center;
    padding: 8px 12px;
    border-bottom: 1px solid var(--border);
    font-size: 12.5px;
  }
  .tr:last-child {
    border-bottom: 0;
  }
  .tr.th {
    position: sticky;
    top: 0;
    background: var(--bg-3);
    font-family: var(--mono);
    font-size: 10px;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--text-mute);
  }
  .c-when {
    font-family: var(--mono);
    font-size: 11.5px;
    color: var(--text-dim);
    font-variant-numeric: tabular-nums;
  }
  .c-who {
    display: flex;
    flex-direction: column;
    min-width: 0;
  }
  .who-name {
    color: var(--text);
  }
  .who-name.you {
    color: var(--accent);
  }
  .who-fp {
    font-family: var(--mono);
    font-size: 10px;
    color: var(--text-mute);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .c-what {
    color: var(--text);
  }
  .c-seq {
    font-family: var(--mono);
    font-size: 11px;
    color: var(--text-mute);
    text-align: right;
    font-variant-numeric: tabular-nums;
  }
  .empty {
    padding: 26px;
    text-align: center;
    color: var(--text-mute);
    font-size: 12.5px;
  }
  .empty.err {
    color: var(--err);
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
