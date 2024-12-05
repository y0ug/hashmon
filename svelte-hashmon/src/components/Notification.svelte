<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  export let notification: { open: boolean; message: string; severity: 'success' | 'error' | 'info' | 'warning' };

  const dispatch = createEventDispatcher();

  const close = () => {
    dispatch('close');
  };
</script>

<!-- {#if notification.open} -->
<!--   <div class={`alert alert-${notification.severity} shadow-lg fixed top-5 right-5 z-50`}> -->
<!--     <div> -->
<!--       <span>{notification.message}</span> -->
<!--       <button class="btn btn-sm btn-ghost" on:click={close}>✕</button> -->
<!--     </div> -->
<!--   </div> -->
<!-- {/if} -->
