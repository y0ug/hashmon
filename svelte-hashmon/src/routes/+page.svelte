<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import { deleteHash } from '../lib/api';
  import type { HashStatus } from '../models/Hash';
  import ConfirmationDialog from '../components/ConfirmationDialog.svelte';
  import Notification from '../components/Notification.svelte';

	let { data }: { data: PageData } = $props();
  let hashes = data.hashes;

  const dispatch = createEventDispatcher();

  let loading = false;
  let dialogOpen = $state(false);
  let hashToDelete: HashStatus | null = $state(null);
  let notification = $state({ open: false, message: '', severity: 'success' });

  const handleView = (sha256: string) => {
    // navigate(`/hashes/${sha256}`);
  };

  const handleDeleteClick = (hash: HashStatus) => {
    hashToDelete = hash;
    dialogOpen = true;
  };

  const handleConfirmDelete = async () => {
    if (!hashToDelete) return;
    loading = true;
    try {
      await deleteHash(hashToDelete.sha256);
      dispatch('hashDeleted', hashToDelete.sha256);
      notification = { open: true, message: 'Hash deleted successfully.', severity: 'success' };
    } catch (error) {
      console.error(error);
      notification = { open: true, message: 'Failed to delete hash.', severity: 'error' };
    } finally {
      dialogOpen = false;
      hashToDelete = null;
      loading = false;
    }
  };

  const handleCancelDelete = () => {
    dialogOpen = false;
    hashToDelete = null;
  };
</script>

<div>
  <h2 class="text-2xl mb-4">Hash List</h2>
  {#if hashes.length === 0}
    <p>No hashes available.</p>
  {:else}
    <table class="table w-full">
      <thead>
        <tr>
          <th>Actions</th>
          <th>Filename</th>
          <th>Build ID</th>
          <th>Last Checked</th>
          <th>Alerted By</th>
          <th>SHA256</th>
        </tr>
      </thead>
      <tbody>
        {#each hashes as hash}
          <tr class={Object.values(hash.providers).some(p => p) ? 'bg-red-100' : ''}>
            <td>
              <button class="btn btn-sm btn-primary mr-2">
                <a href="/hash/{hash.sha256}">View</a>
              </button>
              <button class="btn btn-sm btn-error" onclick={() => handleDeleteClick(hash)}>
                Delete
              </button>
            </td>
            <td>{hash.filename}</td>
            <td>{hash.build_id}</td>
            <td>{new Date(hash.last_check_at).toLocaleString()}</td>
            <td>{hash.alerted_by?.join(', ') || 'None'}</td>
            <td>{hash.sha256}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}

  <!-- Confirmation Dialog -->
  {#if dialogOpen && hashToDelete}
    <ConfirmationDialog
      open={dialogOpen}
      title="Confirm Deletion"
      content={`Are you sure you want to delete the hash for "${hashToDelete.filename}"? This action cannot be undone.`}
      on:confirm={handleConfirmDelete}
      on:cancel={handleCancelDelete}
      confirmText="Delete"
      cancelText="Cancel"
    />
  {/if}

  <!-- Notification -->
  {#if notification.open}
    <Notification
      {notification}
      on:close={() => notification.open = false}
    />
  {/if}
</div>
