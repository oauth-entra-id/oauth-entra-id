import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ReactQueryDevtools as QueryDevTools } from '@tanstack/react-query-devtools';
import { StrictMode } from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router';
import { scan } from 'react-scan';
import App from './App';

import './styles.css';

scan({
  enabled: true,
});

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false, // This is not recommended just for demo purposes
      retry: 1, // Also not recommended, just for demo purposes
    },
  },
});

const rootElement = document.getElementById('app');
if (rootElement && !rootElement.innerHTML) {
  const root = ReactDOM.createRoot(rootElement);
  root.render(
    <StrictMode>
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <App />
        </BrowserRouter>
        <QueryDevTools initialIsOpen={false} />
      </QueryClientProvider>
    </StrictMode>,
  );
}
