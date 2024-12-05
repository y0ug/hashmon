<script lang="ts">
  import { onMount } from 'svelte';
  import { login } from '../../lib/auth';
  import { isAuthenticated } from '../../lib/stores';
  import { goto } from '$app/navigation';
  
  let authenticated: boolean = false;
  
  const unsubscribe = isAuthenticated.subscribe(value => {
    authenticated = value;
  });
  
  onMount(() => {
    if (authenticated) {
      goto('/');
    }
  });
</script>

<div class="flex flex-col items-center justify-center h-screen bg-base-100">
  <div class="text-center">
    <h1 class="text-4xl font-bold mb-4">Welcome to HashMon Dashboard</h1>
    <p class="mb-6">Please log in to continue.</p>
    <button class="btn btn-primary" on:click="{login}">
      Login with OAuth2
    </button>
  </div>
</div>

<style>
  /* Optional styles */
</style>
