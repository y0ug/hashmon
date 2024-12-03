import axios from 'axios';
import { HashesResponse, HashDetailResponse, NewHash } from '../models/Hash';
import { getAccessToken } from '../utils/auth'; // We'll create this utility next

// Set the base URL of your backend API
const API_BASE_URL = 'http://127.0.0.1:8808'; // Adjust as needed

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true, // Include cookies if needed
});

// Request interceptor to handle unauthorized requests
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      // Optionally, you can redirect to login or display a notification
      //window.location.href = '/login'; // Ensure you have a login route
    }
    return Promise.reject(error);
  }
);



// Export the axios instance
export default api;


// Get all hashes
export const getAllHashes = async (): Promise<HashesResponse> => {
  const response = await api.get<HashesResponse>('/api/hashes');
  return response.data;
};

// Get hash details
export const getHashDetail = async (sha256: string): Promise<HashDetailResponse> => {
  const response = await api.get<HashDetailResponse>(`/api/hashes/${sha256}`);
  return response.data;
};

// Add a new hash
export const addHash = async (newHash: NewHash): Promise<NewHash> => {
  const response = await api.put<NewHash>('/api/hashes', newHash);
  return response.data;
};

// Delete a hash
export const deleteHash = async (sha256: string): Promise<void> => {
  await api.delete(`/api/hashes/${sha256}`);
};
