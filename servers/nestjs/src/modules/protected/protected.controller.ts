import type { Request } from 'express';
import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { ProtectRouteGuard } from '~/guards/protect-route.guard';

@Controller('protected')
@UseGuards(ProtectRouteGuard)
export class ProtectedController {
  constructor() {}

  @Get('user-info')
  getUserInfo(@Req() req: Request) {
    return { user: req.userInfo };
  }
}
