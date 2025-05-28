import express, { type Router } from 'express';
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
    if (!userInfo.isApp && !userInfo.injectedData) {
      await injectData({ randomNumber: getRandomNumber() });
    }
  }),
  protectedRouter,
);

function getRandomNumber() {
  return Math.floor(Math.random() * 100);
}
