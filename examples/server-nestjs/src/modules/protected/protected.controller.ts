import { Controller, Get, HttpException, Post, Req, Res, UseGuards } from '@nestjs/common';
import type { Request, Response } from 'express';
import { handleOnBehalfOf } from 'oauth-entra-id/nestjs';
import z from 'zod';
import { ProtectRouteGuard } from '~/guards/protect-route.guard';
// biome-ignore lint/style/useImportType: NestJS
import { ProtectedService } from './protected.service';

const zB2BSchemas = z.object({
  b2bServiceName: z.enum(['express', 'fastify', 'honojs']),
});

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
    handleOnBehalfOf(req, res);
  }

  @Post('get-b2b-info')
  async getB2BInfo(@Req() req: Request) {
    const { data: body, error: bodyError } = zB2BSchemas.safeParse(req.body);
    if (bodyError) throw new HttpException('Invalid params', 400);
    const data = await this.protectedService.fetchB2BInfo(req.oauthProvider, body.b2bServiceName);
    return data;
  }

  @Get('b2b-info')
  sendB2BInfo(@Req() req: Request) {
    if (req.userInfo?.isB2B === false) throw new HttpException('Unauthorized', 401);
    const randomPokemon = this.protectedService.generateRandomPokemon();
    return { pokemon: randomPokemon, server: 'nestjs' };
  }
}
