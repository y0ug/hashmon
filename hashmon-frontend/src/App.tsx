import React, { useContext } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { Helmet, HelmetProvider } from 'react-helmet-async';
import { Container, AppBar, Toolbar, Typography, Button } from '@mui/material';
import HomePage from './pages/HomePage';
import HashPage from './pages/HashPage';
import AuthCallback from './components/AuthCallback';
import LoginPage from './pages/LoginPage'; // Create this component
import NotFoundPage from './pages/NotFoundPage'; // Create this component
import { AuthProvider, AuthContext } from './contexts/AuthContext';
import ProtectedRoute from './components/ProtectedRoute';

const App: React.FC = () => {
  return (
    <HelmetProvider>
      <Router>
        <AuthProvider>
          <AppContent />
        </AuthProvider>
      </Router>
    </HelmetProvider>
  );
};

const AppContent: React.FC = () => {
  const { isAuthenticated, login, logout, loading } = useContext(AuthContext);

  return (
    <>
      <Helmet>
        <title>HashMon Dashboard</title> {/* Default Title */}
        <meta name="description" content="Manage and monitor your hashes efficiently." />
      </Helmet>
      <AppBar position="static">
        <Toolbar>
          <Typography variant="h6" sx={{ flexGrow: 1 }}>
            HashMon Dashboard
          </Typography>
          {!loading && (
            <>
              {isAuthenticated ? (
                <Button color="inherit" onClick={logout}>
                  Logout
                </Button>
              ) : (
                <Button color="inherit" onClick={login}>
                  Login
                </Button>
              )}
            </>
          )}
        </Toolbar>
      </AppBar>
      <Container maxWidth="xl" sx={{ mt: 8 }}>
        <Routes>
          <Route
            path="/"
            element={
              <ProtectedRoute>
                <HomePage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/hashes/:sha256"
            element={
              <ProtectedRoute>

                <HashPage />
              </ProtectedRoute>
            }
          />
          <Route path="/auth/callback" element={<AuthCallback />} />
          <Route path="/login" element={<LoginPage />} />
          <Route path="*" element={<NotFoundPage />} />
        </Routes>
      </Container>
    </>
  );
};

export default App;
