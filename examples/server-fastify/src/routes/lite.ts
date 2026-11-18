import type { FastifyPluginAsyncTypebox } from '@fastify/type-provider-typebox';
import { Type as t } from '@sinclair/typebox';
import axios from 'axios';
import { OAuthError } from 'oauth-entra-id';
import { z } from 'zod';
import { serversMap } from '~/env';
import { HttpException } from '~/error/HttpException';
import { liteProvider } from '~/oauth';
import { generateRandomPokemon } from '~/utils/generate';

// The lite provider of the package: no cookies, no encryption, no login. It only verifies plain app tokens and gets them.

const tSchemas = {
  getB2BInfo: t.Object({
    app: t.Union([t.Literal('express'), t.Literal('nestjs'), t.Literal('honojs')]),
  }),
};

const zB2BResponse = z.object({
  pokemon: z.string().trim().min(1).max(32),
  server: z.enum(['express', 'nestjs', 'honojs']),
});

export const liteRouter: FastifyPluginAsyncTypebox = async (app) => {
  app.get('/b2b-info', async (req, _reply) => {
    const header = req.headers.authorization;
    const token = header?.startsWith('Bearer ') ? header.slice('Bearer '.length) : undefined;

    const { meta, error } = await liteProvider.$verifyJwt(token);
    if (error) throw new OAuthError(error);
    if (meta.isApp === false) throw new HttpException('Unauthorized', 401);

    return { pokemon: generateRandomPokemon(), server: 'fastify', meta };
  });

  app.post('/get-b2b-info', { schema: { body: tSchemas.getB2BInfo } }, async (req, _reply) => {
    const body = req.body as { app: 'express' | 'nestjs' | 'honojs' };

    const { result, error } = await liteProvider.tryGetB2BToken({ app: body.app });
    if (error) throw new OAuthError(error);

    const axiosResponse = await axios.get(`${serversMap[body.app]}/lite/b2b-info`, {
      headers: { Authorization: `Bearer ${result.token}` },
    });
    const { data: b2bRes, error: b2bResError } = zB2BResponse.safeParse(axiosResponse.data);
    if (b2bResError) throw new HttpException('Invalid response from B2B service', 500);

    return { ...b2bRes, isCached: result.isCached, expiresAt: result.expiresAt };
  });
};
