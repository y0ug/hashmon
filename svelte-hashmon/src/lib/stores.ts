import { writable } from 'svelte/store';
import type { User } from '../models/User';

export const isAuthenticated = writable<boolean>(false);
export const user = writable<User | null>(null);
export const loading = writable<boolean>(true);
