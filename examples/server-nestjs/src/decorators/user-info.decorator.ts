import { type ExecutionContext, createParamDecorator } from '@nestjs/common';
import type { Request } from 'express';

export const UserInfo = createParamDecorator((data: string, ctx: ExecutionContext) => {
  const req = ctx.switchToHttp().getRequest<Request>();
  return req.userInfo;
});
