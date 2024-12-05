<script>
  import { error } from '@sveltejs/kit';
  import NotFoundPage from './not-found/+page.svelte';
  import { goto } from '$app/navigation';
</script>

{#if error.status === 404}
  <NotFoundPage />
{:else}
  <div class="flex flex-col items-center justify-center h-screen bg-base-100">
    <h1 class="text-6xl font-bold mb-4">{error.status}</h1>
    <h2 class="text-2xl mb-4">{error.message}</h2>
    <button class="btn btn-primary mt-4" on:click={() => goto('/')}>
      Go to Home Page
    </button>
  </div>
{/if}
