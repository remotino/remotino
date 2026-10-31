<script lang="ts">
  import { ui } from "$lib/state.svelte";
  import Unlock from "$lib/components/Unlock.svelte";
  import Shell from "$lib/components/Shell.svelte";
</script>

{#if ui.screen === "unlock"}
  <Unlock />
{:else}
  <Shell />
{/if}
