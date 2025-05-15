import { Controller, Get, HttpException, Post, Req, Res, UseGuards } from '@nestjs/common';
import axios from 'axios';
import type { Request, Response } from 'express';
import { handleOnBehalfOf } from 'oauth-entra-id/nestjs';
import z from 'zod';
import { env } from '~/env';
import { ProtectRouteGuard } from '~/guards/protect-route.guard';

const zAvailableServers = z.enum(['express', 'fastify', 'honojs']);

const zB2BSchemas = z.object({
  b2bServiceName: zAvailableServers,
});

const zB2BResponse = z.object({
  pokemon: z.string().trim().min(1).max(32),
  server: zAvailableServers,
});

const serversMap = {
  express: env.EXPRESS_URL,
  fastify: env.FASTIFY_URL,
  honojs: env.HONOJS_URL,
};

const pokemon = [
  'Bulbasaur',
  'Charmander',
  'Squirtle',
  'Caterpie',
  'Butterfree',
  'Pidgey',
  'Rattata',
  'Ekans',
  'Pikachu',
  'Vulpix',
  'Jigglypuff',
  'Zubat',
  'Diglett',
  'Meowth',
  'Psyduck',
  'Poliwag',
  'Abra',
  'Machop',
  'Geodude',
  'Haunter',
  'Onix',
  'Cubone',
  'Magikarp',
  'Eevee',
  'Snorlax',
  'Mew',
];

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

  @Post('b2b')
  async b2b(@Req() req: Request, @Res() res: Response) {
    const { data: body, error: bodyError } = zB2BSchemas.safeParse(req.body);
    if (bodyError) throw new HttpException('Invalid params', 400);

    const result = await req.oauthProvider.getB2BToken({ b2bServiceName: body.b2bServiceName });
    const serverUrl = serversMap[body.b2bServiceName];
    const axiosResponse = await axios.get(`${serverUrl}/protected/b2b-info`, {
      headers: { Authorization: `Bearer ${result.b2bAccessToken}` },
    });

    const { data, error } = zB2BResponse.safeParse(axiosResponse.data);
    if (error) throw new HttpException('Invalid B2B response', 500);
    return data;
  }

  @Get('b2b-info')
  getB2BInfo(@Req() req: Request) {
    if (req.userInfo?.isB2B === false) throw new HttpException('Unauthorized', 401);
    const randomPokemon = pokemon[Math.floor(Math.random() * pokemon.length)];
    return { pokemon: randomPokemon, server: 'nestjs' };
  }
}
