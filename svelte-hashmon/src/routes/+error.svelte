<script>
  import { page } from "$app/stores";
  import { goto } from "$app/navigation";
</script>

<div class="flex flex-col items-center justify-center h-screen bg-base-100">
  <h1 class="text-6xl font-bold mb-4">{$page.status}</h1>
  <h2 class="text-2xl mb-4">{$page.error?.message}</h2>
  <button class="btn btn-primary mt-4" on:click={() => goto("/")}>
    Go to Home Page
  </button>
</div>
