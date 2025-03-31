import type { Request, Response } from 'express';
import { Controller, Req, Res, Post, HttpCode } from '@nestjs/common';
import { handleAuthentication, handleCallback, handleLogout } from 'oauth-entra-id/nestjs';

@Controller('auth')
export class AuthController {
  @Post('authenticate')
  @HttpCode(200)
  async generateAuthUrl(@Req() req: Request, @Res() res: Response) {
    await handleAuthentication(req, res);
  }

  @Post('callback')
  @HttpCode(200)
  async exchangeCodeForToken(@Req() req: Request, @Res() res: Response) {
    await handleCallback(req, res);
  }

  @Post('logout')
  @HttpCode(200)
  async generateLogoutUrl(@Req() req: Request, @Res() res: Response) {
    handleLogout(req, res);
  }
}
