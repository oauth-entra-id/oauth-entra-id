import axios from 'axios';
import express, { type Router } from 'express';
import { expressOAuthProvider, handleOnBehalfOf } from 'oauth-entra-id/express';
import { z } from 'zod/v4';
import { serversMap } from '~/env';
import { HttpException } from '~/error/HttpException';
import { generateRandomPokemon } from '~/utils/generate';

const zAvailableServers = z.enum(['nestjs', 'fastify', 'honojs']);
const zGetB2BInfoBody = z.object({ app: zAvailableServers });

export const protectedRouter: Router = express.Router();

protectedRouter.get('/user-info', (req, res) => {
  res.status(200).json({ user: req.userInfo });
});

protectedRouter.post('/on-behalf-of', handleOnBehalfOf());

protectedRouter.get('/b2b-info', (req, res) => {
  if (req.userInfo?.isApp === false) throw new HttpException('Unauthorized', 401);
  res.status(200).json({ pokemon: generateRandomPokemon(), server: 'express' });
});

const zB2BResponse = z.object({
  pokemon: z.string().trim().min(1).max(32),
  server: zAvailableServers,
});

protectedRouter.post('/get-b2b-info', async (req, res) => {
  const { data: body, error: bodyError } = zGetB2BInfoBody.safeParse(req.body);
  if (bodyError) throw new HttpException('Invalid params', 400);

  const { result, error } = await expressOAuthProvider.tryGetB2BToken({ app: body.app });
  if (error) throw new HttpException('Failed to get B2B token', 500);

  const serverUrl = serversMap[body.app];
  const axiosResponse = await axios.get(`${serverUrl}/protected/b2b-info`, {
    headers: { Authorization: `Bearer ${result.token}` },
  });

  const { data: b2bRes, error: b2bResError } = zB2BResponse.safeParse(axiosResponse.data);
  if (b2bResError) throw new HttpException('Invalid B2B response', 500);
  res.status(200).json(b2bRes);
});
