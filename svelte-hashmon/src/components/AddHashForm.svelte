<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import { addHash } from '../lib/api';
  import { loading } from '$lib/stores';
  import type { NewHash } from '../models/Hash';

  const dispatch = createEventDispatcher();

  let formData: NewHash = {
    sha256: '',
    filename: '',
    build_id: '',
  };

  let notification = { open: false, message: '', severity: 'success' };

  const handleChange = (e: Event) => {
    const target = e.target as HTMLInputElement;
    formData = { ...formData, [target.name]: target.value };
  };

  const handleSubmit = async (e: Event) => {
    e.preventDefault();

    if (!formData.sha256 || !formData.filename) {
      notification = { open: true, message: 'All fields are required.', severity: 'error' };
      return;
    }

    loading.set(true);

    try {
      await addHash(formData);
      formData = { sha256: '', filename: '', build_id: '' };
      dispatch('hashAdded');
    } catch (error) {
      console.error(error);
      notification = { open: true, message: 'Failed to add hash.', severity: 'error' };
    } finally {
      loading.set(false);
    }
  };
</script>

<div>
  <h2 class="text-2xl mb-4">Add New Hash</h2>
  <form on:submit|preventDefault={handleSubmit} class="p-4 bg-base-200 rounded">
    <div class="mb-4">
      <label class="label">
        <span class="label-text">SHA256*</span>
      </label>
      <input
        type="text"
        name="sha256"
        bind:value={formData.sha256}
        class="input input-bordered w-full"
        required
      />
    </div>
    <div class="mb-4">
      <label class="label">
        <span class="label-text">Filename</span>
      </label>
      <input
        type="text"
        name="filename"
        bind:value={formData.filename}
        class="input input-bordered w-full"
      />
    </div>
    <div class="mb-4">
      <label class="label">
        <span class="label-text">Build ID</span>
      </label>
      <input
        type="text"
        name="build_id"
        bind:value={formData.build_id}
        class="input input-bordered w-full"
      />
    </div>
    <button
      type="submit"
      class="btn btn-primary"
      disabled={loading}
    >
      {#if loading}
        Adding...
      {:else}
        Add Hash
      {/if}
    </button>
  </form>
  {#if notification.open}
    <div class={`alert alert-${notification.severity}`}>
      <div>
        <span>{notification.message}</span>
        <button class="btn btn-sm btn-ghost" on:click={() => notification.open = false}>✕</button>
      </div>
    </div>
  {/if}
</div>
