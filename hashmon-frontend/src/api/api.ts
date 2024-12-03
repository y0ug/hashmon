import axios from 'axios';
import { HashesResponse, HashDetailResponse, NewHash } from '../models/Hash';

// Set the base URL of your backend API
const API_BASE_URL = 'http://localhost:8808'; // Adjust as needed

export const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Get all hashes
export const getAllHashes = async (): Promise<HashesResponse> => {
  const response = await api.get<HashesResponse>('/hashes');
  return response.data;
};

// Get hash details
export const getHashDetail = async (sha256: string): Promise<HashDetailResponse> => {
  const response = await api.get<HashDetailResponse>(`/hashes/${sha256}`);
  return response.data;
};

// Add a new hash
export const addHash = async (newHash: NewHash): Promise<NewHash> => {
  const response = await api.put<NewHash>('/hashes', newHash);
  return response.data;
};

// Delete a hash
export const deleteHash = async (sha256: string): Promise<void> => {
  await api.delete(`/hashes/${sha256}`);
};
