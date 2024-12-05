import axios, { AxiosError, type AxiosResponse, type AxiosRequestConfig } from 'axios';
import { type HttpResp } from '../models/HttpResp';
import { type HashesResponse, type HashDetailResponse, type NewHash } from '../models/Hash';
import { type User } from '../models/User';

// Set the base URL of your backend API
const API_BASE_URL = 'http://127.0.0.1:8808'; // Adjust as needed

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true, // Include cookies in requests
});

// Flag to indicate if the token is being refreshed
let isRefreshing = false;

// Queue to hold pending requests while token is being refreshed
let failedQueue: Array<{
  resolve: (value: AxiosResponse<any, any>) => void;
  reject: (error: any) => void;
}> = [];

// Process the queue once token refresh is done
const processQueue = (error: any, response?: AxiosResponse<any, any>) => {
  failedQueue.forEach((prom) => {
    if (error) {
      prom.reject(error);
    } else if (response) {
      prom.resolve(response);
    }
  });

  failedQueue = [];
};

// Response interceptor to handle 401 errors
api.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as AxiosRequestConfig & { _retry?: boolean };

    const currentPath = window.location.pathname;
    // If error response is 401 and the request hasn't been retried yet
    if (error.response?.status === 401 && originalRequest && !originalRequest._retry) {
      if (isRefreshing) {
        // If a refresh is already in progress, queue the request
        return new Promise<AxiosResponse<any>>((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        })
          .then((resp) => resp)
          .catch((err) => Promise.reject(err));
      }

      originalRequest._retry = true;
      isRefreshing = true;

      return new Promise<AxiosResponse<any>>(async (resolve, reject) => {
        try {
          // Attempt to refresh the token
          const response = await axios.post<HttpResp<null>>(
            `${API_BASE_URL}/auth/refresh`,
            {},
            {
              withCredentials: true, // Ensure cookies are sent
            }
          );

          if (response.data.status === 'success') {
            // Notify all queued requests to retry with the new token
            processQueue(null, response);
            resolve(api(originalRequest));
          } else {
            // If refresh failed, reject all queued requests
            processQueue(new Error(response.data.message), undefined);
            reject(new Error(response.data.message));
          }
        } catch (err) {
          // If refresh fails, reject all queued requests and handle logout
          processQueue(err, undefined);
          // Optionally, redirect to login
          if (currentPath !== '/login') {
            // window.location.href = '/login';
          }
          reject(err);
        } finally {
          isRefreshing = false;
        }
      });
    }

    return Promise.reject(error);
  }
);

// Export the axios instance
export default api;

// API Functions

// Get all hashes
export const getAllHashes = async (): Promise<HashesResponse> => {
  const response = await api.get<HttpResp<HashesResponse>>('/api/hashes');
  if (response.data.status === 'success' && response.data.data) {
    return response.data.data;
  } else {
    throw new Error(response.data.message || 'Failed to fetch hashes.');
  }
};

// Get hash details
export const getHashDetail = async (sha256: string): Promise<HashDetailResponse> => {
  const response = await api.get<HttpResp<HashDetailResponse>>(`/api/hashes/${sha256}`);
  if (response.data.status === 'success' && response.data.data) {
    return response.data.data;
  } else {
    throw new Error(response.data.message || 'Failed to fetch hash details.');
  }
};

// Add a new hash
export const addHash = async (newHash: NewHash): Promise<NewHash> => {
  const response = await api.put<HttpResp<NewHash>>('/api/hashes', newHash);
  if (response.data.status === 'success' && response.data.data) {
    return response.data.data;
  } else {
    throw new Error(response.data.message || 'Failed to add hash.');
  }
};

// Delete a hash
export const deleteHash = async (sha256: string): Promise<void> => {
  const response = await api.delete<HttpResp<null>>(`/api/hashes/${sha256}`);
  if (response.data.status !== 'success') {
    throw new Error(response.data.message || 'Failed to delete hash.');
  }
};

// Get User Info
export const getUserInfo = async (): Promise<User> => {
  const response = await api.get<HttpResp<User>>('/user');
  if (response.data.status === 'success' && response.data.data) {
    return response.data.data;
  } else {
    throw new Error(response.data.message || 'Failed to fetch user information.');
  }
};
