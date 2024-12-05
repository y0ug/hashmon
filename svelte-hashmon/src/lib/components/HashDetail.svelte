<script lang="ts">
  import type { HashStatus } from '$lib/models/Hash';
  import { createEventDispatcher } from 'svelte';


  export let hash: HashStatus | null = null;

  // Event dispatcher in case you need to emit events to parent components
  const dispatch = createEventDispatcher();

</script>

{#if hash}
  <div class="bg-base-200 p-6 rounded-lg shadow-lg">
    <h2 class="text-2xl font-bold mb-4">Hash Detail</h2>
    <ul class="list-none space-y-2">
      <li>
        <strong>SHA256:</strong> {hash.sha256}
      </li>
      <li>
        <strong>Filename:</strong> {hash.filename}
      </li>
      <li>
        <strong>Build ID:</strong> {hash.build_id}
      </li>
      <li>
        <strong>Last Checked:</strong> {new Date(hash.last_check_at).toLocaleString()}
      </li>
      <li>
        <strong>Alerted By:</strong> {hash.alerted_by?.join(', ') || 'None'}
      </li>
      <li>
        <strong>Providers:</strong>
        <ul class="list-disc ml-5">
          {#each Object.entries(hash.providers) as [provider, status]}
            <li class={status ? 'text-red-500' : 'text-green-500'}>
              {provider}: {status ? 'True' : 'False'}
            </li>
          {/each}
        </ul>
      </li>
    </ul>
    <button class="btn btn-primary mt-4" on:click="{dispatch('goBack')}">
      Back
    </button>
  </div>
{:else}
  <div class="text-center">
    <h2 class="text-2xl font-bold">Hash Not Found</h2>
    <button class="btn btn-primary mt-4" on:click="{dispatch('goBack')}">
      Go Back
    </button>
  </div>
{/if}

<style>
</style>
