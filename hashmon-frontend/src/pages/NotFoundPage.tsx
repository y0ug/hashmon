import React from 'react';
import { Typography, Box } from '@mui/material';
import { Link } from 'react-router-dom';

const NotFoundPage: React.FC = () => {
  return (
    <Box textAlign="center" mt={10}>
      <Typography variant="h3" gutterBottom>
        404 - Page Not Found
      </Typography>
      <Typography variant="body1">
        The page you're looking for doesn't exist. Go back to the{' '}
        <Link to="/">Home Page</Link>.
      </Typography>
    </Box>
  );
};

export default NotFoundPage;
