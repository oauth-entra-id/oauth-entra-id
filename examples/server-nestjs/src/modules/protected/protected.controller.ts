import { Body, Controller, Get, Post, Req, Res } from '@nestjs/common';
import type { Request, Response } from 'express';
import { handleOnBehalfOf } from 'oauth-entra-id/nestjs';
import { IsApp } from '~/decorators/app.decorator';
import { generateRandomPokemon } from '~/utils/generate';
// biome-ignore lint/style/useImportType: NestJS
import { GetB2BInfoDto } from './protected.dto';
// biome-ignore lint/style/useImportType: NestJS
import { ProtectedService } from './protected.service';

@Controller('protected')
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

  @IsApp()
  @Get('b2b-info')
  sendB2BInfo() {
    return { pokemon: generateRandomPokemon(), server: 'nestjs' };
  }

  @Post('get-b2b-info')
  async getB2BInfo(@Body() body: GetB2BInfoDto) {
    return await this.protectedService.fetchB2BInfo(body.app);
  }
}
