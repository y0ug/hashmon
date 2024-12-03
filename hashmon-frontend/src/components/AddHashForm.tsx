import React, { useState } from 'react';
import { addHash, getAllHashes } from '../api/api';
import { NewHash, HashStatus } from '../models/Hash';
import {
  TextField,
  Button,
  Typography,
  Paper,
  Box,
} from '@mui/material';
import Notification from './Notification';

const AddHashForm: React.FC = () => {
  const [formData, setFormData] = useState<NewHash>({
    sha256: '',
    filename: '',
    build_id: '',
  });
  const [loading, setLoading] = useState<boolean>(false);
  const [notification, setNotification] = useState<{ open: boolean; message: string; severity: 'success' | 'error' }>({
    open: false,
    message: '',
    severity: 'success',
  });

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      await addHash(formData);
      setNotification({ open: true, message: 'Hash added successfully.', severity: 'success' });
      setFormData({ sha256: '', filename: '', build_id: '' });
    } catch (error) {
      console.error(error);
      setNotification({ open: true, message: 'Failed to add hash.', severity: 'error' });
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <Typography variant="h4" gutterBottom>
        Add New Hash
      </Typography>
      <Paper sx={{ padding: 2 }}>
        <Box component="form" onSubmit={handleSubmit} noValidate>
          <TextField
            label="SHA256"
            name="sha256"
            value={formData.sha256}
            onChange={handleChange}
            required
            fullWidth
            margin="normal"
          />
          <TextField
            label="Filename"
            name="filename"
            value={formData.filename}
            onChange={handleChange}
            fullWidth
            margin="normal"
          />
          <TextField
            label="Build ID"
            name="buildid"
            value={formData.build_id}
            onChange={handleChange}
            fullWidth
            margin="normal"
          />
          <Button type="submit" variant="contained" color="primary" disabled={loading}>
            {loading ? 'Adding...' : 'Add Hash'}
          </Button>
        </Box>
      </Paper>
      <Notification
        open={notification.open}
        message={notification.message}
        severity={notification.severity}
        onClose={() => setNotification({ ...notification, open: false })}
      />
    </>
  );
};

export default AddHashForm;
