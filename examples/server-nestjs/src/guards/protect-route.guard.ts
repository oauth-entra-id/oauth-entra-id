import { type CanActivate, type ExecutionContext, Injectable } from '@nestjs/common';
import type { Request, Response } from 'express';
import { isAuthenticated } from 'oauth-entra-id/nestjs';
@Injectable()
export class ProtectRouteGuard implements CanActivate {
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const httpContext = context.switchToHttp();
    const req = httpContext.getRequest<Request>();
    const res = httpContext.getResponse<Response>();
    return await isAuthenticated(req, res, ({ userInfo, injectData }) => {
      if (!userInfo.isB2B && !userInfo.injectedData) {
        injectData({ randomNumber: getRandomNumber() });
      }
    });
  }
}

function getRandomNumber() {
  return Math.floor(Math.random() * 100);
}
