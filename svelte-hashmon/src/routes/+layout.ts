import { checkAuthStatus } from "$lib/auth";
import type { LayoutLoad } from './$types';
import { apiFetch } from "$lib/api";
import type { User } from "$lib/models/User";
import type { HttpResp } from "$lib/models/HttpResp";
import { isAuthenticated, user, loading } from "$lib/stores";

// Disable SSR
// export const prerender = false;
// export const ssr = false;

export const load: LayoutLoad = async ({ fetch }) => {
  try {
    loading.set(true);
    const response = await fetch('http://127.0.0.1:8808/auth/status', { credentials: 'include', });
    if (response.status === 401) {
      const response = await fetch('http://127.0.0.1:8808/auth/refresh', { credentials: 'include', });
    }
    const data: HttpResp<User> = await response.json();
    loading.set(false);
    if (data.status === 'success' && data.data) {
      isAuthenticated.set(true);
      user.set(data.data.user);
    }

    console.log('Auth status checked ');
  } catch (error) {
    loading.set(false);
    // console.log('Auth Status Error:', error);
    console.log('Auth status failed');
    isAuthenticated.set(false);
    user.set(null);
  } finally {
    // console.log('Auth status checked finally');
    console.log('Auth status end loading');
  }
  return {}
};
