import express, { type Router } from 'express';
import { type CallbackFunction, OAuthError } from 'oauth-entra-id';
import { protectRoute } from 'oauth-entra-id/express';
import { getRandomNumber } from '~/utils/generate';
import { authRouter } from './auth';
import { liteRouter } from './lite';
import { mobileAuthRouter, mobileProtectedRouter } from './mobile';
import { protectedRouter } from './protected';
import { publicRouter } from './public';

export const routesRouter: Router = express.Router();

const callbackFunc: CallbackFunction = async ({ userInfo, tryInjectData }) => {
  if (userInfo.isApp === false && !userInfo.injectedData) {
    const inj = await tryInjectData(getRandomNumber());
    if (inj.error) throw new OAuthError(inj.error);
  }
};

routesRouter.use('/', publicRouter);
routesRouter.use('/auth', authRouter);
routesRouter.use('/auth/mobile', mobileAuthRouter);
routesRouter.use('/lite', liteRouter);
// Registered before '/protected' on purpose: the cookie middleware of that mount must not wrap the Bearer routes.
routesRouter.use('/protected/mobile', mobileProtectedRouter);
routesRouter.use('/protected', protectRoute(callbackFunc), protectedRouter);
