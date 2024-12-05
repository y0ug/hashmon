<script lang="ts">
  import { isAuthenticated, user, loading } from '../lib/stores';
  import { logout } from '../lib/auth';
  import { goto } from '$app/navigation';
  
  const handleLogout = async () => {
    await logout();
    goto('/login');
  };
</script>

<nav class="navbar bg-base-100 shadow-lg fixed top-0 left-0 right-0 z-50">
  <div class="navbar-start">
    <a class="btn btn-ghost normal-case text-xl" href="/">HashMon Dashboard</a>
  </div>
  <div class="navbar-end">
    {#if !$loading}
      {#if $isAuthenticated && $user}
        <div class="flex items-center space-x-4">
          <div class="avatar">
            <div class="w-10 rounded-full bg-secondary text-white flex items-center justify-center">
              {#if $user.name}
                { $user.name.charAt(0).toUpperCase() }
              {/if}
            </div>
          </div>
          <span>{ $user.name }</span>
          <button class="btn btn-ghost" on:click={handleLogout}>Logout</button>
        </div>
      {:else}
        <a href="/login" class="btn btn-primary">Login</a>
      {/if}
    {/if}
  </div>
</nav>
