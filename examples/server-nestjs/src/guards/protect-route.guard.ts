import { type CanActivate, type ExecutionContext, ForbiddenException, Injectable } from '@nestjs/common';
import type { Reflector } from '@nestjs/core';
import type { Request, Response } from 'express';
import { type CallbackFunction, OAuthError } from 'oauth-entra-id';
import { isAuthenticated } from 'oauth-entra-id/nestjs';
import { IS_APP_KEY } from '~/decorators/app.decorator';
import { IS_PUBLIC_KEY } from '~/decorators/public.decorator';
import { getRandomNumber } from '~/utils/generate';

const callbackFunc: CallbackFunction = async ({ userInfo, tryInjectData }) => {
  if (!userInfo.isApp && !userInfo.injectedData) {
    const inj = await tryInjectData(getRandomNumber());
    if (inj.error) throw new OAuthError(inj.error);
  }
};

@Injectable()
export class ProtectRoute implements CanActivate {
  constructor(private reflector: Reflector) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) return true;

    const httpContext = context.switchToHttp();
    const req = httpContext.getRequest<Request>();
    const res = httpContext.getResponse<Response>();
    const authenticated = await isAuthenticated(req, res, callbackFunc);

    const isApp = this.reflector.getAllAndOverride<boolean>(IS_APP_KEY, [context.getHandler(), context.getClass()]);
    if (isApp && req.userInfo?.isApp !== true) throw new ForbiddenException();

    return authenticated;
  }
}
