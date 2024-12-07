import { apiFetch } from './api';
import { isAuthenticated, user, loading } from './stores';
import type { User } from '$lib/models/User';
import { get } from 'svelte/store';
import type { HttpResp } from './models/HttpResp';

export const login = () => {
  window.location.href = 'http://127.0.0.1:8808/auth/login';
};

export const logout = async () => {
  try {
    loading.set(true);
    const response = await apiFetch(fetch, '/auth/logout');
    const data: HttpResp<User> = await response.json();
    loading.set(false);
    if (data.status === 'success') {
      isAuthenticated.set(false);
      user.set(null);
      // Redirect to login or home
    } else {
      throw new Error(data.message);
    }
    isAuthenticated.set(false);
  } catch (error) {
    loading.set(false);
    isAuthenticated.set(false);
    user.set(null);
    console.log('Logout failed:', error);
  } finally {

  }
};

export const checkAuthStatus = async () => {
};
