import React, { useEffect, useState } from 'react';
import { HashStatus } from '../models/Hash';
import HashList from '../components/HashList';
import AddHashForm from '../components/AddHashForm';
import { getAllHashes } from '../api/api';
import { CircularProgress, Typography } from '@mui/material';
import Grid from '@mui/material/Grid2';
import Notification from '../components/Notification';

const HomePage: React.FC = () => {
  const [hashes, setHashes] = useState<HashStatus[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [notification, setNotification] = useState<{
    open: boolean;
    message: string;
    severity: 'success' | 'error';
  }>({
    open: false,
    message: '',
    severity: 'success',
  });

  // Function to fetch hashes from the backend
  const fetchHashes = async () => {
    try {
      const data = await getAllHashes();
      console.log('Fetched hashes:', data); // Verify data structure
      setHashes(data.hashes);
    } catch (error) {
      console.error(error);
      setNotification({
        open: true,
        message: 'Failed to fetch hashes.',
        severity: 'error',
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHashes();
  }, []);

  // Callback to refresh hashes after adding a new one
  const handleHashAdded = () => {
    fetchHashes();
    setNotification({
      open: true,
      message: 'Hash added successfully.',
      severity: 'success',
    });
  };

  return (
    <div>
      {/* <Typography variant="h3" gutterBottom> */}
      {/*   HashMon Dashboard */}
      {/* </Typography> */}
      <Grid container spacing={2}>
        <Grid size={{ xs: 12, sm: 4 }}>
          <AddHashForm onHashAdded={handleHashAdded} setNotification={setNotification} />
        </Grid>
        <Grid size={{ xs: 12, sm: 10 }}>
          {loading ? (
            <CircularProgress />
          ) : (
            <HashList hashes={hashes} setNotification={setNotification} />
          )}
        </Grid>
      </Grid>
      <Notification
        open={notification.open}
        message={notification.message}
        severity={notification.severity}
        onClose={() => setNotification({ ...notification, open: false })}
      />
    </div>
  );
};

export default HomePage;
