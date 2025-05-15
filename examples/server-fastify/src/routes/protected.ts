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
    oboServiceNames: t.Array(t.String(), { minItems: 1 }),
  }),
  b2b: t.Object({
    b2bServiceName: t.Union([t.Literal('express'), t.Literal('nestjs'), t.Literal('honojs')]),
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

    const { oboServiceNames } = req.body;

    const results = await oauthProvider.getTokenOnBehalfOf({
      accessToken: req.microsoftInfo.rawAccessToken,
      oboServiceNames,
    });

    for (const result of results) {
      const { oboAccessToken, oboRefreshToken } = result;
      reply.setCookie(oboAccessToken.name, oboAccessToken.value, oboAccessToken.options);
      if (oboRefreshToken) reply.setCookie(oboRefreshToken.name, oboRefreshToken.value, oboRefreshToken.options);
    }

    return { tokensSet: results.length };
  });

  app.post('/b2b', { schema: { body: tSchemas.b2b } }, async (req, reply) => {
    const { b2bServiceName } = req.body;
    const result = await oauthProvider.getB2BToken({ b2bServiceName });
    const serverUrl = serversMap[b2bServiceName];
    const axiosResponse = await axios.get(`${serverUrl}/protected/b2b-info`, {
      headers: { Authorization: `Bearer ${result.b2bAccessToken}` },
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
