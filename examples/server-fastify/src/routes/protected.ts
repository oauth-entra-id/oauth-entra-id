import type { FastifyPluginAsyncTypebox } from '@fastify/type-provider-typebox';
import { Type as t } from '@sinclair/typebox';
import axios from 'axios';
import { z } from 'zod';
import { env } from '~/env';
import { HttpException } from '~/error/HttpException';
import { protectRoute } from '~/middlewares/protect-route';
import { oauthProvider } from '~/oauth';

const tSchemas = {
  onBehalfOf: t.Object({
    serviceNames: t.Array(t.String(), { minItems: 1 }),
  }),
  getB2BInfo: t.Object({
    appName: t.Union([t.Literal('express'), t.Literal('nestjs'), t.Literal('honojs')]),
  }),
};

export const protectedRouter: FastifyPluginAsyncTypebox = async (app) => {
  app.addHook('preHandler', protectRoute);

  app.get('/user-info', (req, reply) => {
    return { user: req.userInfo };
  });

  app.post('/on-behalf-of', { schema: { body: tSchemas.onBehalfOf } }, async (req, reply) => {
    if (req.userInfo?.isApp === true) throw new HttpException('B2B users cannot use OBO', 401);

    const { serviceNames } = req.body;

    const { results, error } = await oauthProvider.getTokenOnBehalfOf({
      accessToken: req.accessTokenInfo.jwt,
      serviceNames,
    });
    if (error) throw new HttpException(error.message, error.statusCode);

    for (const { accessToken } of results) {
      reply.setCookie(accessToken.name, accessToken.value, accessToken.options);
    }

    return { tokensSet: results.length };
  });

  app.post('/get-b2b-info', { schema: { body: tSchemas.getB2BInfo } }, async (req, reply) => {
    const { appName } = req.body;
    const { result, error } = await oauthProvider.getB2BToken({ appName });
    if (error) throw new HttpException(error.message, error.statusCode);
    const { accessToken } = result;

    const serverUrl = serversMap[appName];
    const axiosResponse = await axios.get(`${serverUrl}/protected/b2b-info`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    const { data: b2bRes, error: b2bResError } = zB2BResponse.safeParse(axiosResponse.data);
    if (b2bResError) throw new HttpException('Invalid response from B2B service', 500);
    return b2bRes;
  });

  app.get('/b2b-info', (req, reply) => {
    if (req.userInfo?.isApp === false) throw new HttpException('Unauthorized', 401);
    const randomPokemon = pokemon[Math.floor(Math.random() * pokemon.length)];
    return { pokemon: randomPokemon, server: 'fastify' };
  });
};

const zB2BResponse = z.object({
  pokemon: z.string().trim().min(1).max(32),
  server: z.enum(['express', 'nestjs', 'honojs']),
});

const serversMap = {
  express: env.EXPRESS_URL,
  nestjs: env.NESTJS_URL,
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
