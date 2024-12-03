import React, { createContext, useState, useEffect, ReactNode } from 'react';
import axios from '../api/api'; // Use the configured axios instance
import { useNavigate } from 'react-router-dom';
import { debug } from 'console';

interface AuthContextType {
  isAuthenticated: boolean;
  login: () => void;
  logout: () => void;
  loading: boolean;
}

export const AuthContext = createContext<AuthContextType>({
  isAuthenticated: false,
  login: () => { },
  logout: () => { },
  loading: true,
});

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(true);
  const navigate = useNavigate();

  // Function to initiate login
  const login = () => {
    window.location.href = 'http://127.0.0.1:8808/auth/login'; // Backend's OAuth2 login endpoint
  };

  // Function to handle logout
  const logout = async () => {
    try {
      await axios.post('/auth/logout'); // Backend's logout endpoint
      setIsAuthenticated(false);
      navigate('/login'); // Redirect to login or home page
    } catch (error) {
      console.error('Logout failed:', error);
      // Optionally, display a notification
    }
  };

  // Function to check authentication status
  const checkAuthStatus = async () => {
    try {
      await axios.get('/auth/status'); // Backend's status endpoint
      setIsAuthenticated(true);
    } catch (error) {
      setIsAuthenticated(false);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    checkAuthStatus();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <AuthContext.Provider value={{ isAuthenticated, login, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
};
