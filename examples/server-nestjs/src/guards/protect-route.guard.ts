import { type CanActivate, type ExecutionContext, Injectable } from '@nestjs/common';
import type { Request, Response } from 'express';
import { type CallbackFunction, OAuthError } from 'oauth-entra-id';
import { isAuthenticated } from 'oauth-entra-id/nestjs';

const callbackFunction: CallbackFunction = async ({ userInfo, injectData }) => {
  if (!userInfo.isApp && !userInfo.injectedData) {
    const { error } = await injectData({ randomNumber: getRandomNumber() });
    if (error) throw new OAuthError(error);
  }
};

@Injectable()
export class ProtectRouteGuard implements CanActivate {
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const httpContext = context.switchToHttp();
    const req = httpContext.getRequest<Request>();
    const res = httpContext.getResponse<Response>();
    return await isAuthenticated(req, res, callbackFunction);
  }
}

function getRandomNumber() {
  return Math.floor(Math.random() * 100);
}
