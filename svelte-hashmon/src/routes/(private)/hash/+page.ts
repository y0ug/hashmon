import type { PageLoad } from './$types';
import { apiFetch, getAllHashes } from '$lib/api';
import type { HttpResp } from '$lib/models/HttpResp';
import type { HashesResponse } from '$lib/models/Hash';
// import { isAuthenticated } from '$lib/stores';

export const load: PageLoad = async ({ fetch }) => {

  const response = await apiFetch(fetch, '/api/hashes', { credentials: 'include', });
  const data: HttpResp<HashesResponse> = await response.json();
  if (data.status === 'success' && data.data) {
    return { "hashes": data.data } //await getAllHashes()
  }
};
