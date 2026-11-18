import axios from 'axios';
import express, { type Router } from 'express';
import { OAuthError } from 'oauth-entra-id';
import { z } from 'zod';
import { serversMap } from '~/env';
import { HttpException } from '~/error/HttpException';
import { liteProvider } from '~/oauth';
import { generateRandomPokemon } from '~/utils/generate';

// The lite provider of the package: no cookies, no encryption, no login. It only verifies plain app tokens and gets them.

const zAvailableServers = z.enum(['nestjs', 'fastify', 'honojs']);

const zGetB2BInfoBody = z.object({ app: zAvailableServers });

const zB2BResponse = z.object({
  pokemon: z.string().trim().min(1).max(32),
  server: zAvailableServers,
});

export const liteRouter: Router = express.Router();

liteRouter.get('/b2b-info', async (req, res) => {
  const header = req.headers.authorization;
  const token = header?.startsWith('Bearer ') ? header.slice('Bearer '.length) : undefined;

  const { meta, error } = await liteProvider.$verifyJwt(token);
  if (error) throw new OAuthError(error);
  if (meta.isApp === false) throw new HttpException('Unauthorized', 401);

  res.status(200).json({ pokemon: generateRandomPokemon(), server: 'express', meta });
});

liteRouter.post('/get-b2b-info', async (req, res) => {
  const { data: body, error: bodyError } = zGetB2BInfoBody.safeParse(req.body);
  if (bodyError) throw new HttpException('Invalid params', 400);

  const { result, error } = await liteProvider.tryGetB2BToken({ app: body.app });
  if (error) throw new OAuthError(error);

  const axiosResponse = await axios.get(`${serversMap[body.app]}/lite/b2b-info`, {
    headers: { Authorization: `Bearer ${result.token}` },
  });
  const { data: b2bRes, error: b2bResError } = zB2BResponse.safeParse(axiosResponse.data);
  if (b2bResError) throw new HttpException('Invalid B2B response', 500);

  res.status(200).json({ ...b2bRes, isCached: result.isCached, expiresAt: result.expiresAt });
});
