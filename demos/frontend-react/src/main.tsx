import { scan } from 'react-scan';

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ReactQueryDevtools as QueryDevTools } from '@tanstack/react-query-devtools';
import { RouterProvider, createRouter } from '@tanstack/react-router';
import { TanStackRouterDevtools as RouterDevTools } from '@tanstack/react-router-devtools';
import { StrictMode } from 'react';
import ReactDOM from 'react-dom/client';

import { routeTree } from './routeTree.gen';

import './styles.css';

scan({
  enabled: true,
});

export const queryClient = new QueryClient();

const router = createRouter({
  routeTree,
  context: { queryClient },
  defaultPreload: 'intent',
  scrollRestoration: true,
  defaultStructuralSharing: true,
  defaultPreloadStaleTime: 0,
});

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router;
  }
}

const rootElement = document.getElementById('app');
if (rootElement && !rootElement.innerHTML) {
  const root = ReactDOM.createRoot(rootElement);
  root.render(
    <StrictMode>
      <QueryClientProvider client={queryClient}>
        <RouterProvider router={router} />
        <RouterDevTools router={router} initialIsOpen={false} />
        <QueryDevTools initialIsOpen={false} />
      </QueryClientProvider>
    </StrictMode>,
  );
}
