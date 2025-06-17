import { Controller, HttpCode, Post, Req, Res } from '@nestjs/common';
import type { Request, Response } from 'express';
import { handleAuthentication, handleCallback, handleLogout } from 'oauth-entra-id/nestjs';

@Controller('auth')
export class AuthController {
  @Post('authenticate')
  @HttpCode(200)
  async getAuthUrl(@Req() req: Request, @Res() res: Response) {
    await handleAuthentication(req, res);
  }

  @Post('callback')
  @HttpCode(200)
  async getTokenByCode(@Req() req: Request, @Res() res: Response) {
    await handleCallback(req, res);
  }

  @Post('logout')
  @HttpCode(200)
  async getLogoutUrl(@Req() req: Request, @Res() res: Response) {
    await handleLogout(req, res);
  }
}
