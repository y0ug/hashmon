<script>
  import { isAuthenticated, loading } from "$lib/stores";
  let { children } = $props();
</script>

{#if $loading}
  <div class="flex justify-center mt-20">
    <div class="loader">Loading...</div>
  </div>
{:else if $isAuthenticated === false}
  <div class="flex justify-center mt-20">Error: Not authenticated</div>
{:else}
  <div class="flex justify-center mt-20">
    {@render children()}
  </div>
{/if}
