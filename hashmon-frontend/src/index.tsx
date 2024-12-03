import { createRoot } from 'react-dom/client';
import { StrictMode } from 'react';
import App from './App';
import CssBaseline from '@mui/material/CssBaseline';
import { ThemeProvider } from '@mui/material/styles';
import theme from './theme';

// Import Roboto font
import '@fontsource/roboto/300.css'; // Thin
import '@fontsource/roboto/400.css'; // Regular
import '@fontsource/roboto/500.css'; // Medium
import '@fontsource/roboto/700.css'; // Bold

const rootElement = document.getElementById('root');
const root = createRoot(rootElement!);

root.render(
  <StrictMode>
    <ThemeProvider theme={theme} defaultMode="light">
      <CssBaseline />
      <App />
    </ThemeProvider>
  </StrictMode>
  ,
);

// ReactDOM.render(
//   <React.StrictMode>
//     <CssBaseline />
//     <App />
//   </React.StrictMode>,
//   document.getElementById('root')
// );
