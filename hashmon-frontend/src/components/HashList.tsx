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
import ConfirmationDialog from './ConfirmationDialog'; // Import the ConfirmationDialog

interface HashListProps {
  hashes: HashStatus[];
  setNotification: React.Dispatch<
    React.SetStateAction<{
      open: boolean;
      message: string;
      severity: 'success' | 'error';
    }>
  >;
}

const HashList: React.FC<HashListProps> = ({ hashes, setNotification }) => {
  const [loading, setLoading] = useState<boolean>(false);

  // State for Confirmation Dialog
  const [dialogOpen, setDialogOpen] = useState<boolean>(false);
  const [hashToDelete, setHashToDelete] = useState<HashStatus | null>(null);

  const navigate = useNavigate();


  // Open the confirmation dialog
  const handleDeleteClick = (hash: HashStatus) => {
    setHashToDelete(hash);
    setDialogOpen(true);
  };

  // Confirm deletion
  const handleConfirmDelete = async () => {
    if (!hashToDelete) return;
    setLoading(true);
    try {
      await deleteHash(hashToDelete.sha256);
      // setHashes(hashes.filter((hash) => hash.sha256 !== hashToDelete.sha256));
      setNotification({
        open: true,
        message: 'Hash deleted successfully.',
        severity: 'success',
      });
      // #TODO remove from the hash list by passing a function from HomePage
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
      setLoading(false);
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
              {hashes.map((hash: HashStatus) => {
                const hasProvider = Object.values(hash.providers).some((provider) => provider);
                return (
                  <TableRow key={hash.sha256}
                    style={{ backgroundColor: hasProvider ? 'red' : 'inherit' }}>
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
                )
              })}
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


    </>
  );
};

export default HashList;
