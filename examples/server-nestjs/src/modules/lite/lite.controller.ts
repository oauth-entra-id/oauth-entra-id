import { Body, Controller, Get, HttpCode, Post, Req, UnauthorizedException } from '@nestjs/common';
import type { Request } from 'express';
import { OAuthError } from 'oauth-entra-id';
import { Public } from '~/decorators/public.decorator';
import { liteProvider } from '~/oauth';
import { generateRandomPokemon } from '~/utils/generate';
// biome-ignore-start lint/style/useImportType: NestJS
import { LiteGetB2BInfoDto } from './lite.dto';
import { LiteService } from './lite.service';
// biome-ignore-end lint/style/useImportType: NestJS

// The lite provider of the package: no cookies, no encryption, no login. It only verifies plain app tokens and gets them.
// @Public() skips the global cookie guard, the token is verified here with the lite provider.
@Public()
@Controller('lite')
export class LiteController {
  constructor(private readonly liteService: LiteService) {}

  @Get('b2b-info')
  async getB2BInfo(@Req() req: Request) {
    const header = req.headers.authorization;
    const token = header?.startsWith('Bearer ') ? header.slice('Bearer '.length) : undefined;

    const { meta, error } = await liteProvider.$verifyJwt(token);
    if (error) throw new OAuthError(error);
    if (meta.isApp === false) throw new UnauthorizedException();

    return { pokemon: generateRandomPokemon(), server: 'nestjs', meta };
  }

  @Post('get-b2b-info')
  @HttpCode(200)
  async fetchB2BInfo(@Body() body: LiteGetB2BInfoDto) {
    return await this.liteService.fetchB2BInfo(body.app);
  }
}
