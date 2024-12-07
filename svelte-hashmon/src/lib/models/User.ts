export interface User {
  name: string;
  email: string;
  sub: string;
  picture?: string | null;
}

export interface AuthStatusData {
  authenticated: boolean;
  user: User | null;
}

export interface Provider {
  id: string;
  name: string;
  type: string;
}
