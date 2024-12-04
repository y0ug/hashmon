import React, { useContext } from 'react';
import { AuthContext } from '../contexts/AuthContext';
import { Typography, Box } from '@mui/material';

const ProfilePage: React.FC = () => {
  const { user } = useContext(AuthContext);

  if (!user) {
    return (
      <Box textAlign="center" mt={10}>
        <Typography variant="h6">No user information available.</Typography>
      </Box>
    );
  }

  return (
    <Box mt={4}>
      <Typography variant="h4" gutterBottom>
        User Profile
      </Typography>
      <Typography variant="body1">
        <strong>Username:</strong> {user.name}
      </Typography>
      <Typography variant="body1">
        <strong>Email:</strong> {user.email}
      </Typography>
      <Typography variant="body1">
        <strong>Sub:</strong> {user.sub}
      </Typography>
    </Box>
  );
};

export default ProfilePage;
