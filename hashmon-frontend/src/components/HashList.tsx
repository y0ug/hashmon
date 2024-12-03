import React, { useEffect, useState } from 'react';
import { HashStatus } from '../models/Hash';
import { getAllHashes, deleteHash } from '../api/api';
import {
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  IconButton,
  CircularProgress,
  Typography,
} from '@mui/material';
import { Delete, Visibility } from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import Notification from './Notification';
import ConfirmationDialog from './ConfirmationDialog'; // Import the ConfirmationDialog

const HashList: React.FC = () => {
  const [hashes, setHashes] = useState<HashStatus[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [notification, setNotification] = useState<{ open: boolean; message: string; severity: 'success' | 'error' }>({
    open: false,
    message: '',
    severity: 'success',
  });

  // State for Confirmation Dialog
  const [dialogOpen, setDialogOpen] = useState<boolean>(false);
  const [hashToDelete, setHashToDelete] = useState<HashStatus | null>(null);

  const navigate = useNavigate();

  const fetchHashes = async () => {
    try {
      const data = await getAllHashes();
      setHashes(data.hashes);
    } catch (error) {
      console.error(error);
      setNotification({ open: true, message: 'Failed to fetch hashes.', severity: 'error' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHashes();
  }, []);

  // Open the confirmation dialog
  const handleDeleteClick = (hash: HashStatus) => {
    setHashToDelete(hash);
    setDialogOpen(true);
  };

  // Confirm deletion
  const handleConfirmDelete = async () => {
    if (!hashToDelete) return;
    try {
      await deleteHash(hashToDelete.sha256);
      setHashes(hashes.filter((hash) => hash.sha256 !== hashToDelete.sha256));
      setNotification({
        open: true,
        message: 'Hash deleted successfully.',
        severity: 'success',
      });
    } catch (error) {
      console.error(error);
      setNotification({
        open: true,
        message: 'Failed to delete hash.',
        severity: 'error',
      });
    } finally {
      setDialogOpen(false);
      setHashToDelete(null);
    }
  };

  // Cancel deletion
  const handleCancelDelete = () => {
    setDialogOpen(false);
    setHashToDelete(null);
  };

  const handleView = (sha256: string) => {
    navigate(`/hashes/${sha256}`);
  };

  if (loading) {
    return <CircularProgress />;
  }

  return (
    <>
      <Typography variant="h4" gutterBottom>
        Hash List
      </Typography>
      {hashes.length === 0 ? (
        <Typography>No hashes available.</Typography>
      ) : (
        <TableContainer component={Paper}>
          <Table aria-label="hash table">
            <TableHead>
              <TableRow>
                <TableCell align="left">Actions</TableCell>
                <TableCell>Filename</TableCell>
                <TableCell>Build ID</TableCell>
                <TableCell>Last Checked</TableCell>
                <TableCell>Alerted By</TableCell>
                <TableCell>SHA256</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {hashes.map((hash) => (
                <TableRow key={hash.sha256}>
                  <TableCell align="left">
                    <IconButton color="primary" onClick={() => handleView(hash.sha256)}>
                      <Visibility />
                    </IconButton>
                    <IconButton color="error" onClick={() => handleDeleteClick(hash)}>
                      <Delete />
                    </IconButton>
                  </TableCell>
                  <TableCell>{hash.filename}</TableCell>
                  <TableCell>{hash.build_id}</TableCell>
                  <TableCell>{new Date(hash.last_check_at).toLocaleString()}</TableCell>
                  <TableCell>{hash.alerted_by?.join(', ') || 'None'}</TableCell>
                  <TableCell>{hash.sha256}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}


      {/* Confirmation Dialog */}
      <ConfirmationDialog
        open={dialogOpen}
        title="Confirm Deletion"
        content={
          hashToDelete
            ? `Are you sure you want to delete the hash for "${hashToDelete.filename}"? This action cannot be undone.`
            : ''
        }
        onConfirm={handleConfirmDelete}
        onCancel={handleCancelDelete}
        confirmText="Delete"
        cancelText="Cancel"
      />

      {/* Notification Snackbar */}
      <Notification
        open={notification.open}
        message={notification.message}
        severity={notification.severity}
        onClose={() => setNotification({ ...notification, open: false })}
      />
    </>
  );
};

export default HashList;
