<script lang="ts">
	import '../app.css';
	let { children } = $props();
  import { onMount } from 'svelte';
  import Header from '../components/Header.svelte';
  import { checkAuthStatus } from '../lib/auth';
  import { isAuthenticated, loading } from '../lib/stores';

  onMount(() => {
    checkAuthStatus();
  });
</script>

<Header />

{#if $loading}
  <div class="flex justify-center mt-20">
    <div class="loader">Loading...</div>
  </div>
{:else}
{@render children()}
{/if}

<style>
  /* Add any global styles or layout-specific styles here */
</style>

