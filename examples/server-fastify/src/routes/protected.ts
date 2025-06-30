import type { FastifyPluginAsyncTypebox } from '@fastify/type-provider-typebox';
import { Type as t } from '@sinclair/typebox';
import axios from 'axios';
import { z } from 'zod/v4';
import { serversMap } from '~/env';
import { HttpException } from '~/error/HttpException';
import { protectRoute } from '~/middlewares/protect-route';
import { oauthProvider } from '~/oauth';
import { generateRandomPokemon } from '~/utils/generate';

const tSchemas = {
  onBehalfOf: t.Object({
    services: t.Array(t.String(), { minItems: 1 }),
  }),
  getB2BInfo: t.Object({
    app: t.Union([t.Literal('express'), t.Literal('nestjs'), t.Literal('honojs')]),
  }),
};

const zB2BResponse = z.object({
  pokemon: z.string().trim().min(1).max(32),
  server: z.enum(['express', 'nestjs', 'honojs']),
});

export const protectedRouter: FastifyPluginAsyncTypebox = async (app) => {
  app.addHook('preHandler', protectRoute);

  app.get('/user-info', (req, reply) => {
    return { user: req.userInfo };
  });

  app.post('/on-behalf-of', { schema: { body: tSchemas.onBehalfOf } }, async (req, reply) => {
    if (req.userInfo?.isApp === true) throw new HttpException('B2B users cannot use OBO', 401);

    const { services } = req.body;

    const { results } = await oauthProvider.getTokenOnBehalfOf({
      accessToken: req.accessTokenInfo.jwt,
      services,
    });

    for (const { accessToken } of results) {
      reply.setCookie(accessToken.name, accessToken.value, accessToken.options);
    }

    return { tokensSet: results.length };
  });

  app.get('/b2b-info', (req, reply) => {
    if (req.userInfo?.isApp === false) throw new HttpException('Unauthorized', 401);
    return { pokemon: generateRandomPokemon(), server: 'fastify' };
  });

  app.post('/get-b2b-info', { schema: { body: tSchemas.getB2BInfo } }, async (req, reply) => {
    const { app } = req.body;
    const { result, error } = await oauthProvider.tryGetB2BToken({ app });
    if (error) throw new HttpException('Failed to get B2B token', 500);

    const serverUrl = serversMap[app];
    const axiosResponse = await axios.get(`${serverUrl}/protected/b2b-info`, {
      headers: { Authorization: `Bearer ${result.token}` },
    });

    const { data: b2bRes, error: b2bResError } = zB2BResponse.safeParse(axiosResponse.data);
    if (b2bResError) throw new HttpException('Invalid response from B2B service', 500);
    return b2bRes;
  });
};
