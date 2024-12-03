import React from 'react';
import { Grid } from '@mui/material';
import HashList from '../components/HashList';
import AddHashForm from '../components/AddHashForm';

const HomePage: React.FC = () => {
  return (
    <Grid container spacing={4}>
      <Grid item xs={12} md={8}>
        <HashList />
      </Grid>
      <Grid item xs={12} md={4}>
        <AddHashForm />
      </Grid>
    </Grid>
  );
};

export default HomePage;
