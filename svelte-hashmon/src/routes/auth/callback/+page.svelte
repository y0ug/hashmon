<script lang="ts">
  import { onMount } from 'svelte';
  import { checkAuthStatus } from '../../../lib/auth';
  import { isAuthenticated } from '../../../lib/stores';
  import { goto } from '$app/navigation';
  
  onMount(async () => {
    await checkAuthStatus();
    // Redirect based on authentication status
    if ($isAuthenticated) {
      goto('/');
    } else {
      goto('/login');
    }
  });
</script>

<div class="flex flex-col items-center mt-20">
  <div class="loader">Loading...</div>
  <p>Processing authentication...</p>
</div>
