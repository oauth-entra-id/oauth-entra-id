import { Body, Controller, Get, Post, Req, Res } from '@nestjs/common';
import type { Request, Response } from 'express';
import type { UserInfo as UserInfoType } from 'oauth-entra-id';
import { handleOnBehalfOf } from 'oauth-entra-id/nestjs';
import { IsApp } from '~/decorators/app.decorator';
import { UserInfo } from '~/decorators/user-info.decorator';
import { generateRandomPokemon } from '~/utils/generate';
// biome-ignore-start lint/style/useImportType: NestJS
import { GetB2BInfoDto } from './protected.dto';
import { ProtectedService } from './protected.service';
// biome-ignore-end lint/style/useImportType: NestJS

@Controller('protected')
export class ProtectedController {
  constructor(private readonly protectedService: ProtectedService) {}

  @Get('user-info')
  getUserInfo(@UserInfo() userInfo: UserInfoType) {
    return { user: userInfo };
  }

  @Post('on-behalf-of')
  async getTokenOnBehalfOf(@Req() req: Request, @Res() res: Response) {
    await handleOnBehalfOf(req, res);
  }

  @IsApp()
  @Get('b2b-info')
  sendB2BInfo() {
    return { pokemon: generateRandomPokemon(), server: 'nestjs' };
  }

  @Post('get-b2b-info')
  async getB2BInfo(@Body() body: GetB2BInfoDto) {
    return await this.protectedService.fetchB2BInfo(body.app, body.azureId);
  }
}
