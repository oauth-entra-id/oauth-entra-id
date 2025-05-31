import express, { type Router } from 'express';
import { handleAuthentication, handleCallback, handleLogout } from 'oauth-entra-id/express';

export const authRouter: Router = express.Router();

authRouter.post('/authenticate', handleAuthentication());
authRouter.post('/callback', handleCallback());
authRouter.post('/logout', handleLogout());
