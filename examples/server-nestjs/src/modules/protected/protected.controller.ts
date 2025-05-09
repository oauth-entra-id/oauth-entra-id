import { Controller, Get, Post, Req, Res, UseGuards } from '@nestjs/common';
import type { Request, Response } from 'express';
import { handleOnBehalfOf } from 'oauth-entra-id/nestjs';
import { ProtectRouteGuard } from '~/guards/protect-route.guard';

@Controller('protected')
@UseGuards(ProtectRouteGuard)
export class ProtectedController {
  @Get('user-info')
  getUserInfo(@Req() req: Request) {
    return { user: req.userInfo };
  }

  @Post('on-behalf-of')
  async getTokenOnBehalfOf(@Req() req: Request, @Res() res: Response) {
    handleOnBehalfOf(req, res);
  }
}
