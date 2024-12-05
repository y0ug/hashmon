<script lang="ts">
  import { onMount } from 'svelte';
  import HashDetail from '$lib/components/HashDetail.svelte';
  import Notification from '$lib/components/Notification.svelte';
  import type { HashStatus } from '$lib/models/Hash';
  import { goto } from '$app/navigation';
  import { page } from '$app/stores';
  import { getHashDetail } from '$lib/api';
 	import type { PageData } from './$types';

 
  let { data }: { data: PageData } = $props();
  let notification = {
    open: false,
    message: '',
    severity: 'success' as 'success' | 'error',
  };
  const goBack = () => {
    window.history.back();
  };

</script>

<div class="container mx-auto px-4 mt-20">
  {#if data.hash}
    <HashDetail hash={data.hash} on:goBack="{goBack}" />
  {:else}
    <div class="text-center">
      <h2 class="text-2xl font-bold">Hash Not Found</h2>
      <button class="btn btn-primary mt-4" on:click={goBack()}>Go Back</button>
    </div>
  {/if}

  <!-- Notification -->
  <Notification
    open="{notification.open}"
    message="{notification.message}"
    severity="{notification.severity}"
    on:close="{() => notification.open = false}"
  />
</div>
