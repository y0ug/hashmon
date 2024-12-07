<script lang="ts">
  import { isAuthenticated, user, loading } from "$lib/stores";
  import { logout } from "$lib/auth";
  import { goto } from "$app/navigation";
  import { onDestroy } from "svelte";
  import { get } from "svelte/store";
  import type { User } from "$lib/models/User";

  // Local variables to hold store values
  let isAuth: boolean;
  let isLoading: boolean;
  let currentUser: User | null;

  // Subscribe to the stores
  const unsubscribeAuth = isAuthenticated.subscribe((value) => {
    isAuth = value;
  });

  const unsubscribeLoading = loading.subscribe((value) => {
    isLoading = value;
  });

  const unsubscribeUser = user.subscribe((value) => {
    currentUser = value;
  });

  // Cleanup subscriptions when component is destroyed
  onDestroy(() => {
    unsubscribeAuth();
    unsubscribeLoading();
    unsubscribeUser();
  });

  const handleLogout = async () => {
    await logout();
    console.log("Logged out successfully");
    goto("/login");
  };

  const switchAuth = async () => {
    isAuthenticated.set(!get(isAuthenticated));
    console.log("Switched auth status " + get(isAuthenticated));
  };
</script>

<nav class="navbar bg-base-100 shadow-lg fixed top-0 left-0 right-0 z-50">
  <div class="navbar-start">
    <a class="btn btn-ghost normal-case text-xl" href="/">HashMon Dashboard</a>
    <a class="btn btn-ghost" href="/hash">Hash</a>
  </div>
  <div class="navbar-end">
    {#if !isLoading}
      {#if isAuth && currentUser}
        <div class="flex items-center space-x-4">
          {#if currentUser.picture}
            <div class="avatar">
              <div class="w-12 rounded-full">
                <img
                  src={currentUser.picture}
                  alt="{currentUser.name}'s Profile Picture"
                  class="w-12 h-12 rounded-full object-cover"
                  onerror={(e: Event) => {
                    // Fallback to initials if image fails to load
                    const img = e.target as HTMLImageElement;
                    img.onerror = null; // Prevent infinite loop if fallback fails
                    img.src = ""; // Remove src to hide the broken image icon
                  }}
                />
              </div>
            </div>
          {:else}
            <div class="avatar placeholder">
              <div
                class="bg-neutral text-neutral-content w-12 h-12 rounded-full flex items-center justify-center text-xl"
              >
                {#if currentUser.name}
                  {currentUser.name.charAt(0).toUpperCase()}
                {/if}
              </div>
            </div>
          {/if}
          <a href="/profile" class="btn btn-ghost">
            <span>{currentUser.name}</span>
          </a>
          <button class="btn btn-ghost" onclick={handleLogout}>Logout</button>
        </div>
      {:else}
        <a href="/login" class="btn btn-primary">Login</a>
      {/if}
    {/if}
    <a onclick={switchAuth} class="btn btn-primary">Switch</a>
  </div>
</nav>

<style>
</style>
