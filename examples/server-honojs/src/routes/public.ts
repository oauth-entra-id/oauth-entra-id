import { Hono } from 'hono';
import { env } from '~/env';

export const publicRouter = new Hono();

publicRouter.get('/', (c) => c.json({ message: 'Hello World' }));
publicRouter.get('/health', (c) => c.text('OK'));
publicRouter.get('/app-info', (c) =>
  c.json({
    current: 'blue',
    blue: { '1': env.BLUE1_AZURE_CLIENT_ID, '2': env.BLUE2_AZURE_CLIENT_ID },
    red: { '1': env.RED1_AZURE_CLIENT_ID, '2': env.RED2_AZURE_CLIENT_ID },
    yellow: { '1': env.YELLOW1_AZURE_CLIENT_ID, '2': env.YELLOW2_AZURE_CLIENT_ID },
  }),
);
