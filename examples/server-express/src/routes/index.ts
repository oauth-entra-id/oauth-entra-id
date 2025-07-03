import express, { type Router } from 'express';
import { type CallbackFunction, OAuthError } from 'oauth-entra-id';
import { protectRoute } from 'oauth-entra-id/express';
import { getRandomNumber } from '~/utils/generate';
import { authRouter } from './auth';
import { protectedRouter } from './protected';
import { publicRouter } from './public';

export const routesRouter: Router = express.Router();

const callbackFunc: CallbackFunction = async ({ userInfo, tryInjectData }) => {
  if (userInfo.isApp === false && !userInfo.injectedData) {
    const { error } = await tryInjectData(getRandomNumber());
    if (error) throw new OAuthError(error);
  }
};

routesRouter.use('/', publicRouter);
routesRouter.use('/auth', authRouter);
routesRouter.use('/protected', protectRoute(callbackFunc), protectedRouter);
