import type { Request, Response } from 'express';
import { type CanActivate, type ExecutionContext, Injectable } from '@nestjs/common';
import { isAuthenticated } from 'oauth-entra-id/nestjs';
@Injectable()
export class ProtectRouteGuard implements CanActivate {
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<Request>();
    const res = context.switchToHttp().getResponse<Response>();
    return await isAuthenticated(req, res);
  }
}
