export interface User {
  name: string;
  email: string;
  sub: string;
}

export interface AuthStatusData {
  authenticated: boolean;
  user: User | null;
}
