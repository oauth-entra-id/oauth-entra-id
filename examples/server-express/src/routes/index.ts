import express, { type Router } from 'express';
import { OAuthError } from 'oauth-entra-id';
import { protectRoute } from 'oauth-entra-id/express';
import { authRouter } from './auth';
import { protectedRouter } from './protected';
import { publicRouter } from './public';

export const routesRouter: Router = express.Router();

routesRouter.use('/', publicRouter);
routesRouter.use('/auth', authRouter);
routesRouter.use(
  '/protected',
  protectRoute(async ({ userInfo, injectData }) => {
    if (userInfo.isApp === false && !userInfo.injectedData) {
      const { error } = await injectData({ randomNumber: getRandomNumber() });
      if (error) throw new OAuthError(error);
    }
  }),
  protectedRouter,
);

function getRandomNumber() {
  return Math.floor(Math.random() * 100);
}
