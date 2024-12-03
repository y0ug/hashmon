import React, { useEffect, useContext } from 'react';
import { AuthContext } from '../contexts/AuthContext';
import { CircularProgress, Typography, Box } from '@mui/material';
import { useNavigate } from 'react-router-dom';

const AuthCallback: React.FC = () => {
  const { isAuthenticated, loading } = useContext(AuthContext);
  const navigate = useNavigate();

  useEffect(() => {
    if (!loading) {
      if (isAuthenticated) {
        navigate('/'); // Redirect to home or desired protected route
      } else {
        navigate('/login'); // Redirect to login or display an error
      }
    }
  }, [isAuthenticated, loading, navigate]);

  return (
    <Box display="flex" flexDirection="column" alignItems="center" mt={10}>
      <CircularProgress />
      <Typography variant="h6" mt={2}>
        Processing authentication...
      </Typography>
    </Box>
  );
};

export default AuthCallback;
