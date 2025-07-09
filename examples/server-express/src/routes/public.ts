import express, { type Router } from 'express';
import { env } from '~/env';

export const publicRouter: Router = express.Router();

publicRouter.get('/', (_req, res) => {
  res.status(200).json({ message: 'Hello World' });
});

publicRouter.get('/health', (_req, res) => {
  res.status(200).send('OK');
});

publicRouter.get('/app-info', (_req, res) => {
  res.status(200).send({
    current: 'yellow',
    blue: { '1': env.BLUE1_AZURE_CLIENT_ID, '2': env.BLUE2_AZURE_CLIENT_ID },
    red: { '1': env.RED1_AZURE_CLIENT_ID, '2': env.RED2_AZURE_CLIENT_ID },
    yellow: { '1': env.YELLOW1_AZURE_CLIENT_ID, '2': env.YELLOW2_AZURE_CLIENT_ID },
  });
});
