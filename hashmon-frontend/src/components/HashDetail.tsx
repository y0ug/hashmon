import React, { useEffect, useState } from 'react';
import { HashStatus, HashDetailResponse } from '../models/Hash';
import { getHashDetail } from '../api/api';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Typography,
  CircularProgress,
  Paper,
  List,
  ListItem,
  ListItemText,
  Button,
} from '@mui/material';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import Notification from './Notification';

const HashDetailComponent: React.FC = () => {
  const { sha256 } = useParams<{ sha256: string }>();
  const [hash, setHash] = useState<HashStatus | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [notification, setNotification] = useState<{ open: boolean; message: string; severity: 'success' | 'error' }>({
    open: false,
    message: '',
    severity: 'success',
  });

  const navigate = useNavigate();

  const fetchHashDetail = async () => {
    try {
      if (!sha256) throw new Error('SHA256 not provided');
      const data: HashDetailResponse = await getHashDetail(sha256);
      setHash(data.hash);
    } catch (error) {
      console.error(error);
      setNotification({ open: true, message: 'Failed to fetch hash details.', severity: 'error' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHashDetail();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sha256]);

  if (loading) {
    return <CircularProgress />;
  }

  if (!hash) {
    return <Typography variant="h6">Hash not found.</Typography>;
  }

  return (
    <>
      <Button startIcon={<ArrowBackIcon />} onClick={() => navigate(-1)} sx={{ mb: 2 }}>
        Back
      </Button>
      <Typography variant="h4" gutterBottom>
        Hash Detail
      </Typography>
      <Paper sx={{ padding: 2 }}>
        <List>
          <ListItem>
            <ListItemText primary="SHA256" secondary={hash.sha256} />
          </ListItem>
          <ListItem>
            <ListItemText primary="Filename" secondary={hash.filename} />
          </ListItem>
          <ListItem>
            <ListItemText primary="Build ID" secondary={hash.build_id} />
          </ListItem>
          <ListItem>
            <ListItemText
              primary="Last Checked"
              secondary={new Date(hash.last_check_at).toLocaleString()}
            />
          </ListItem>
          <ListItem>
            <ListItemText
              primary="Alerted By"
              secondary={hash.alerted_by?.join(', ') || 'None'}
            />
          </ListItem>
        </List>
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

export default HashDetailComponent;
