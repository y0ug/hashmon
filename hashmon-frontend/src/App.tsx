import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { Container, AppBar, Toolbar, Typography } from '@mui/material';
import HomePage from './pages/HomePage';
import HashPage from './pages/HashPage';

const App: React.FC = () => {
  return (
    <Router>
      <AppBar position="static">
        <Toolbar>
          <Typography variant="h6">HashMon Dashboard</Typography>
        </Toolbar>
      </AppBar>
      <Container sx={{ mt: 4 }}>
        <Routes>
          <Route path="/" element={<HomePage />} />
          <Route path="/hashes/:sha256" element={<HashPage />} />
        </Routes>
      </Container>
    </Router>
  );
};

export default App;
