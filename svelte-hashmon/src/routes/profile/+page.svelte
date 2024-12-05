<script lang="ts">
  import { onMount } from 'svelte';
  import { isAuthenticated, loading, user } from '../../lib/stores';
  import { goto } from '$app/navigation';
  
  let isAuth: boolean;
  let isLoading: boolean;
  let currentUser: { name: string; email: string; sub: string } | null;
  
  const unsubscribeAuth = isAuthenticated.subscribe(value => isAuth = value);
  const unsubscribeLoading = loading.subscribe(value => isLoading = value);
  const unsubscribeUser = user.subscribe(value => currentUser = value);
  
  onMount(() => {
    if (!isAuth && !isLoading) {
      goto('/login');
    }
  });
  
  // Cleanup subscriptions
  onDestroy(() => {
    unsubscribeAuth();
    unsubscribeLoading();
    unsubscribeUser();
  });
</script>

{#if isLoading}
  <div class="flex justify-center items-center h-64">
    <div class="loader">Loading...</div>
  </div>
{:else if isAuth && currentUser}
  <div class="bg-base-200 p-6 rounded-lg shadow-lg">
    <h2 class="text-2xl font-bold mb-4">User Profile</h2>
    <p><strong>Name:</strong> {currentUser.name}</p>
    <p><strong>Email:</strong> {currentUser.email}</p>
    <p><strong>Sub:</strong> {currentUser.sub}</p>
  </div>
{:else}
  <div class="text-center">
    <h2 class="text-2xl font-bold">User Information Not Available</h2>
    <button class="btn btn-primary mt-4" on:click={() => goto('/login')}>Go to Login</button>
  </div>
{/if}
