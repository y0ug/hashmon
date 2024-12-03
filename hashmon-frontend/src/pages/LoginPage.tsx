import React, { useContext } from 'react';
import { Button, Typography, Box } from '@mui/material';
import { AuthContext } from '../contexts/AuthContext';

const LoginPage: React.FC = () => {
  const { login } = useContext(AuthContext);

  return (
    <Box display="flex" flexDirection="column" alignItems="center" mt={10}>
      <Typography variant="h4" gutterBottom>
        Welcome to HashMon Dashboard
      </Typography>
      <Button variant="contained" color="primary" onClick={login}>
        Login with OAuth2
      </Button>
    </Box>
  );
};

export default LoginPage;
