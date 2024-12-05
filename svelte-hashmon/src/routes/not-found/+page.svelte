<script lang="ts">
  import { goto } from '$app/navigation';
</script>

<div class="flex flex-col items-center justify-center h-screen bg-base-100">
  <h1 class="text-6xl font-bold mb-4">404</h1>
  <h2 class="text-2xl mb-4">Page Not Found</h2>
  <p class="mb-6">The page you're looking for doesn't exist.</p>
  <button class="btn btn-primary" on:click={() => goto('/')}>
    Go to Home Page
  </button>
</div>
