import { Body, Controller, Get, HttpException, Post, Req, Res, UseGuards } from '@nestjs/common';
import type { Request, Response } from 'express';
import type { OAuthProvider as OAuthProviderType, UserInfo as UserInfoType } from 'oauth-entra-id';
import { handleOnBehalfOf } from 'oauth-entra-id/nestjs';
import { OAuthProvider } from '~/decorators/oauth.decorator';
import { UserInfo } from '~/decorators/user-info.decorator';
import { ProtectRouteGuard } from '~/guards/protect-route.guard';
// biome-ignore lint/style/useImportType: NestJS
import { GetB2BInfoDto } from './protected.dto';
// biome-ignore lint/style/useImportType: NestJS
import { ProtectedService } from './protected.service';

@Controller('protected')
@UseGuards(ProtectRouteGuard)
export class ProtectedController {
  constructor(private readonly protectedService: ProtectedService) {}

  @Get('user-info')
  getUserInfo(@Req() req: Request) {
    return { user: req.userInfo };
  }

  @Post('on-behalf-of')
  async getTokenOnBehalfOf(@Req() req: Request, @Res() res: Response) {
    await handleOnBehalfOf(req, res);
  }

  @Post('get-b2b-info')
  async getB2BInfo(@Body() body: GetB2BInfoDto, @OAuthProvider() oauthProvider: OAuthProviderType) {
    const data = await this.protectedService.fetchB2BInfo(oauthProvider, body.appName);
    return data;
  }

  @Get('b2b-info')
  sendB2BInfo(@UserInfo() userInfo: UserInfoType) {
    if (userInfo?.isB2B === false) throw new HttpException('Unauthorized', 401);
    const randomPokemon = this.protectedService.generateRandomPokemon();
    return { pokemon: randomPokemon, server: 'nestjs' };
  }
}
