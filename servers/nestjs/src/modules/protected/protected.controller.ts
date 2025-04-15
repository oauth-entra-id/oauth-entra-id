import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import type { Request } from 'express';
import { ProtectRouteGuard } from '~/guards/protect-route.guard';

@Controller('protected')
@UseGuards(ProtectRouteGuard)
export class ProtectedController {
  @Get('user-info')
  getUserInfo(@Req() req: Request) {
    return { user: req.userInfo };
  }
}
