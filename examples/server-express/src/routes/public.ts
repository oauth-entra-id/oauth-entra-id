import express, { type Router } from 'express';
import { env } from '~/env';

export const publicRouter: Router = express.Router();

publicRouter.get('/', (req, res) => {
  res.status(200).json({ message: 'Hello World' });
});

publicRouter.get('/health', (req, res) => {
  res.status(200).send('OK');
});

publicRouter.get('/app-info', (req, res) => {
  res.status(200).send({
    current: 'yellow',
    blue: env.AZURE_BLUE_CLIENT_ID,
    red: env.AZURE_RED_CLIENT_ID,
    yellow: env.AZURE_YELLOW_CLIENT_ID,
  });
});
