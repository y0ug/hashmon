<script lang="ts">
  import { createEventDispatcher } from 'svelte';

  // Define the props that the component expects
  export let open: boolean = false; // Controls the visibility of the dialog
  export let title: string = 'Confirm Action'; // Title of the dialog
  export let content: string = 'Are you sure you want to proceed?'; // Content/message of the dialog
  export let confirmText: string = 'Confirm'; // Text for the confirm button
  export let cancelText: string = 'Cancel'; // Text for the cancel button

  // Event dispatcher to emit events to the parent component
  const dispatch = createEventDispatcher();

  // Function to handle confirm action
  const handleConfirm = () => {
    dispatch('confirm');
  };

  // Function to handle cancel action
  const handleCancel = () => {
    dispatch('cancel');
  };
</script>

{#if open}
  <div class="modal modal-open">
    <div class="modal-box">
      <h3 class="font-bold text-lg">{title}</h3>
      <p class="py-4">{content}</p>
      <div class="modal-action">
        <button class="btn btn-error" on:click={handleConfirm}>{confirmText}</button>
        <button class="btn btn-secondary" on:click={handleCancel}>{cancelText}</button>
      </div>
    </div>
  </div>
{/if}

<style>
  /* Optional: Add custom styles if needed */
</style>
