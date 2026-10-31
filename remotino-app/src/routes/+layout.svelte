<script lang="ts">
  import "$lib/styles/tokens.css";
  import { ui } from "$lib/state.svelte";

  let { children } = $props();

  // Stamp the theme onto <html> so the [data-theme] token overrides apply. $effect reruns
  // whenever the toggle flips it.
  $effect(() => {
    document.documentElement.setAttribute("data-theme", ui.theme);
  });
</script>

{@render children()}
