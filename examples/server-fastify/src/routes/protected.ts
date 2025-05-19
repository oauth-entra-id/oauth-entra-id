import type { FastifyPluginAsyncTypebox } from '@fastify/type-provider-typebox';
import { Type as t } from '@sinclair/typebox';
import axios from 'axios';
import { z } from 'zod';
import { env } from '~/env';
import { HttpException } from '~/error/HttpException';
import protectRoute from '~/middlewares/protect-route';
import { oauthProvider } from '~/oauth';

const tSchemas = {
  onBehalfOf: t.Object({
    servicesNames: t.Array(t.String(), { minItems: 1 }),
  }),
  getB2BInfo: t.Object({
    appName: t.Union([t.Literal('express'), t.Literal('nestjs'), t.Literal('honojs')]),
  }),
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

export const protectedRouter: FastifyPluginAsyncTypebox = async (app) => {
  app.addHook('preHandler', protectRoute);

  app.get('/user-info', (req, reply) => {
    return { user: req.userInfo };
  });

  app.post('/on-behalf-of', { schema: { body: tSchemas.onBehalfOf } }, async (req, reply) => {
    if (req.userInfo?.isB2B === true) throw new HttpException('B2B users cannot use OBO', 401);

    const { servicesNames } = req.body;

    const results = await oauthProvider.getTokenOnBehalfOf({
      accessToken: req.accessTokenInfo.jwt,
      servicesNames,
    });

    for (const { accessToken } of results) {
      reply.setCookie(accessToken.name, accessToken.value, accessToken.options);
    }

    return { tokensSet: results.length };
  });

  app.post('/get-b2b-info', { schema: { body: tSchemas.getB2BInfo } }, async (req, reply) => {
    const { appName } = req.body;
    const { accessToken } = await oauthProvider.getB2BToken({ appName });
    const serverUrl = serversMap[appName];
    const axiosResponse = await axios.get(`${serverUrl}/protected/b2b-info`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    const { data, error } = zB2BResponse.safeParse(axiosResponse.data);
    if (error) throw new HttpException('Invalid response from B2B service', 500);
    return data;
  });

  app.get('/b2b-info', (req, reply) => {
    if (req.userInfo?.isB2B === false) throw new HttpException('Unauthorized', 401);
    const randomPokemon = pokemon[Math.floor(Math.random() * pokemon.length)];
    return { pokemon: randomPokemon, server: 'fastify' };
  });
};
