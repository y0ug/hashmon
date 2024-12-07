<script lang="ts">
  import "../app.css";
  let { children } = $props();
  import Header from "$lib/components/Header.svelte";
  import { isAuthenticated, loading } from "$lib/stores";
</script>

{#if $loading}
  <div class="flex justify-center mt-20">
    <div class="loader">Loading...</div>
  </div>
{:else}
  <Header />
  <div class="flex justify-center mt-20">
    {@render children()}
  </div>
{/if}
