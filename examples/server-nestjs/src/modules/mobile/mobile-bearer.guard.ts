import { type CanActivate, type ExecutionContext, ForbiddenException, Injectable } from '@nestjs/common';
import type { Request } from 'express';
import { mobileOAuthProvider } from '~/oauth';
import { withStatus } from './mobile.utils';

export interface MobileUser {
  azureId: string;
  tenantId: string;
  uniqueId: string;
  roles: string[];
  isApp: false;
  name: string;
  email: string;
}

export interface MobileRequest extends Request {
  mobile?: { jwt: string; user: MobileUser };
}

/** Mobile apps send the access token as a Bearer token, it is verified with the core API of the package. */
@Injectable()
export class MobileBearerGuard implements CanActivate {
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<MobileRequest>();
    const header = req.headers.authorization;
    const token = header?.startsWith('Bearer ') ? header.slice('Bearer '.length) : undefined;

    const at = await mobileOAuthProvider.verifyAccessToken(token);
    if (at.error) throw withStatus(at.error, 401);
    if (at.meta.isApp) throw new ForbiddenException();

    req.mobile = {
      jwt: at.rawJwt,
      user: {
        azureId: at.meta.azureId as string,
        tenantId: at.meta.tenantId as string,
        uniqueId: at.meta.uniqueId as string,
        roles: at.meta.roles as string[],
        isApp: false,
        name: at.meta.name as string,
        email: at.meta.email as string,
      },
    };
    return true;
  }
}
