import React, { createContext, useState, useEffect, ReactNode } from 'react';
import api, { getUserInfo } from '../api/api'; // Import getUserInfo
import { User } from '../models/User'; // Import the User interface
import { useNavigate } from 'react-router-dom';
import { HttpResp } from '../models/HttpResp'; // Import the HttpResp interface
import { AuthStatusData } from '../models/User';

interface AuthContextType {
  isAuthenticated: boolean;
  user: User | null;
  login: () => void;
  logout: () => void;
  loading: boolean;
}

export const AuthContext = createContext<AuthContextType>({
  isAuthenticated: false,
  user: null,
  login: () => { },
  logout: () => { },
  loading: true,
});

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [user, setUser] = useState<User | null>(null); // State to hold user data
  const [loading, setLoading] = useState<boolean>(true);
  const navigate = useNavigate();

  // Function to initiate login
  const login = () => {
    window.location.href = 'http://127.0.0.1:8808/auth/login'; // Backend's OAuth2 login endpoint
  };

  // Function to handle logout
  const logout = async () => {
    try {
      const response = await api.post<HttpResp<null>>('/auth/logout');
      if (response.data.status === 'success') {
        setIsAuthenticated(false);
        setUser(null);
        navigate('/login'); // Redirect to login or home page
      } else {
        throw new Error(response.data.message);
      }
    } catch (error) {
      console.error('Logout failed:', error);
      // Optionally, display a notification
    }
  };

  // Function to check authentication status
  const checkAuthStatus = async () => {
    try {
      const response = await api.get<HttpResp<AuthStatusData>>('/auth/status');
      console.log('Auth Status Response:', response.data); // Log the response data

      if (response.data.status === 'success' && response.data.data) {
        const { authenticated, user } = response.data.data;
        setIsAuthenticated(authenticated);
        setUser(user);
      } else {
        setIsAuthenticated(false);
        setUser(null);
      }
    } catch (error) {
      console.error('Auth Status Error:', error);
      setIsAuthenticated(false);
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    checkAuthStatus();
    // Optionally, set an interval to periodically check auth status
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <AuthContext.Provider value={{ isAuthenticated, user, login, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
};
