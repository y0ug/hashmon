import { apiFetch, getAuthProviders } from '$lib/api';
import type { PageLoad } from './$types';
import { isAuthenticated } from '$lib/stores';
import { goto } from "$app/navigation";
import type { Provider } from '$lib/models/User';
import type { HttpResp } from '$lib/models/HttpResp';

export const load: PageLoad = async ({ fetch }) => {
  const response = await apiFetch(fetch, '/auth/providers', { credentials: 'include', });
  const data: HttpResp<Provider> = await response.json();
  if (data.status === 'success' && data.data) {
    return { "providers": data.data }
  }
};
