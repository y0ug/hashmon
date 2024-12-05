import api from './api';
import { isAuthenticated, user, loading } from './stores';
import type { User } from '../models/User';

export const login = () => {
  window.location.href = 'http://127.0.0.1:8808/auth/login';
};

export const logout = async () => {
  try {
    const response = await api.post('/auth/logout');
    if (response.data.status === 'success') {
      isAuthenticated.set(false);
      user.set(null);
      // Redirect to login or home
    } else {
      throw new Error(response.data.message);
    }
  } catch (error) {
    console.error('Logout failed:', error);
    // Optionally, show notification
  }
};

export const checkAuthStatus = async () => {
  try {
    const response = await api.get('/auth/status');
    if (response.data.status === 'success' && response.data.data.authenticated) {
      isAuthenticated.set(true);
      user.set(response.data.data.user);
    } else {
      isAuthenticated.set(false);
      user.set(null);
    }
  } catch (error) {
    console.error('Auth Status Error:', error);
    isAuthenticated.set(false);
    user.set(null);
  } finally {
    loading.set(false);
  }
};
