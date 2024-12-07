<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  import { isAuthenticated, loading, user } from "$lib/stores";
  import { goto } from "$app/navigation";
  import type { User } from "$lib/models/User";

  let currentUser: User | null;

  const unsubscribeUser = user.subscribe((value) => (currentUser = value));

  // Cleanup subscriptions
  onDestroy(() => {
    unsubscribeUser();
  });
</script>

{#if currentUser}
  <div class="bg-base-200 p-6 rounded-lg shadow-lg max-w-md mx-auto">
    <h2 class="text-2xl font-bold mb-4">User Profile</h2>
    <div class="flex items-center space-x-4 mb-4">
      {#if currentUser.picture}
        <img
          src={currentUser.picture}
          alt="Profile Picture"
          class="w-16 h-16 rounded-full object-cover"
        />
      {:else}
        <div
          class="w-16 h-16 bg-gray-300 rounded-full flex items-center justify-center text-xl text-white"
        >
          {#if currentUser.name}
            {currentUser.name.charAt(0).toUpperCase()}
          {/if}
        </div>
      {/if}
      <div>
        <p class="font-semibold">{currentUser.name}</p>
        <p class="text-sm text-gray-600">{currentUser.email}</p>
      </div>
    </div>
    <p><strong>Sub:</strong> {currentUser.sub}</p>
    <!-- Add more user details as needed -->
  </div>
{/if}
