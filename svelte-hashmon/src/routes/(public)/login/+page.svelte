<script lang="ts">
  import type { PageData } from "./$types";

  let { data }: { data: PageData } = $props();
  let providers = data.providers;

  // Handle login via provider
  const handleLogin = (providerId: string) => {
    window.location.href = `http://127.0.0.1:8808/auth/login/${providerId}`;
  };
</script>

<div class="flex flex-col items-center justify-center h-screen bg-base-100 p-4">
  <div class="text-center mb-8">
    <h1 class="text-4xl font-bold mb-4">Welcome to HashMon Dashboard</h1>
    <p class="mb-6">Please log in using one of the available providers.</p>
  </div>
  <div class="flex flex-col space-y-4">
    {#each providers as provider}
      <button
        class="btn btn-primary w-full flex items-center justify-center"
        onclick={() => handleLogin(provider.name)}
      >
        <svg
          xmlns="http://www.w3.org/2000/svg"
          class="h-6 w-6 mr-2"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
        >
          <!-- Replace with provider-specific icon if available -->
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            stroke-width="2"
            d="M5 13l4 4L19 7"
          />
        </svg>
        Login with {provider.name}
      </button>
    {/each}
  </div>
</div>

<style>
  /* Optional styles */
</style>
