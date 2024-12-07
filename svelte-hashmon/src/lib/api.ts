import type { HttpResp } from '$lib/models/HttpResp';
import type { HashesResponse, HashDetailResponse, NewHash } from '$lib/models/Hash';
import type { Provider } from '$lib/models/User';
import { isAuthenticated } from './stores';

// The base URL of your backend API
const API_BASE_URL = 'http://127.0.0.1:8808';

// List of protected endpoints. If these return 401, we attempt refresh.
const protectedEndpoints: string[] = [
  '/api/hashes',
  '/auth/status',
  '/auth/logout'
];

let isRefreshing = false;
let refreshInProgress: Promise<void> | null = null;

/**
 * Attempts to refresh the authentication tokens by calling `/auth/refresh`.
 * If successful, resolves. If not, rejects.
 */
async function refreshToken(fetch: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>,): Promise<void> {
  isRefreshing = true;
  try {
    const resp = await fetch(`${API_BASE_URL}/auth/refresh`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' }
    });
    const data: HttpResp<null> = await resp.json();
    if (data.status === 'success') {
      // Tokens refreshed
      return;
    } else {
      // Refresh failed
      isAuthenticated.set(false);
      console.log('Failed to refresh token:', data.message);
      // throw new Error(data.message || 'Failed to refresh token.');
    }
  } finally {
    isRefreshing = false;
  }
}

/**
 * A helper function to perform fetch requests and handle:
 * - Protected endpoints 401 errors
 * - Token refresh and request retry
 */
export async function apiFetch(
  fetch: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>,
  input: string,
  init?: RequestInit & { _retry?: boolean }
): Promise<Response> {
  const url = input.startsWith('http') ? input : `${API_BASE_URL}${input}`;
  const response = await fetch(url, {
    ...init,
    credentials: 'include', // Include cookies in requests
    headers: {
      'Content-Type': 'application/json',
      ...(init?.headers || {})
    }
  });

  if (response.status === 401 && !init?._retry) {
    // Check if endpoint is protected
    const endpoint = input.replace(API_BASE_URL, '');
    const isProtected = protectedEndpoints.some((p) => endpoint.startsWith(p));

    if (isProtected) {
      // If a refresh is already in progress, wait for it
      if (isRefreshing && refreshInProgress) {
        await refreshInProgress;
      } else {
        // Start refresh
        try {
          refreshInProgress = refreshToken(fetch);
          await refreshInProgress;
          refreshInProgress = null;
        } catch (e) {
          console.log('Failed to refresh token:', e);
          isAuthenticated.set(false);
        }
      }

      // After refresh, retry the request once
      return apiFetch(fetch, input, { ...init, _retry: true });
    }
  }

  return response;
}

// Exported functions for API endpoints

export async function getAllHashes(): Promise<HashesResponse> {
  const response = await apiFetch('/api/hashes', { method: 'GET' });
  const data: HttpResp<HashesResponse> = await response.json();
  if (data.status === 'success' && data.data) {
    return data.data;
  }
  throw new Error(data.message || 'Failed to fetch hashes.');
}

export async function getHashDetail(sha256: string): Promise<HashDetailResponse> {
  const response = await apiFetch(`/api/hashes/${sha256}`, { method: 'GET' });
  const data: HttpResp<HashDetailResponse> = await response.json();
  if (data.status === 'success' && data.data) {
    return data.data;
  }
  throw new Error(data.message || 'Failed to fetch hash details.');
}

export async function addHash(newHash: NewHash): Promise<NewHash> {
  const response = await apiFetch('/api/hashes', {
    method: 'PUT',
    body: JSON.stringify(newHash)
  });
  const data: HttpResp<NewHash> = await response.json();
  if (data.status === 'success' && data.data) {
    return data.data;
  }
  throw new Error(data.message || 'Failed to add hash.');
}

export async function deleteHash(sha256: string): Promise<void> {
  const response = await apiFetch(`/api/hashes/${sha256}`, { method: 'DELETE' });
  const data: HttpResp<null> = await response.json();
  if (data.status !== 'success') {
    throw new Error(data.message || 'Failed to delete hash.');
  }
}

export async function getAuthProviders(): Promise<Provider[]> {
  const response = await apiFetch('/auth/providers', { method: 'GET' });
  const data: HttpResp<Provider[]> = await response.json();
  if (data.status === 'success' && data.data) {
    return data.data;
  }
  throw new Error(data.message || 'Failed to fetch authentication providers.');
}
