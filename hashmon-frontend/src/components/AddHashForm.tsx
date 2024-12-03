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

interface AddHashFormProps {
  onHashAdded: () => void;
  setNotification: React.Dispatch<
    React.SetStateAction<{
      open: boolean;
      message: string;
      severity: 'success' | 'error';
    }>
  >;
}
const AddHashForm: React.FC<AddHashFormProps> = ({ onHashAdded, setNotification }) => {
  const [formData, setFormData] = useState<NewHash>({
    sha256: '',
    filename: '',
    build_id: '',
  });
  const [loading, setLoading] = useState<boolean>(false);


  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value,
    });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!formData.sha256 || !formData.filename) {
      setNotification({
        open: true,
        message: 'All fields are required.',
        severity: 'error',
      });
      return;
    }

    setLoading(true);

    try {
      await addHash(formData);
      setFormData({ sha256: '', filename: '', build_id: '' });
      onHashAdded();
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
    </>
  );
};

export default AddHashForm;
