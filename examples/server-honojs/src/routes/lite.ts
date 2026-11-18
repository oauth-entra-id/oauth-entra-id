import { zValidator } from '@hono/zod-validator';
import axios from 'axios';
import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { OAuthError } from 'oauth-entra-id';
import { z } from 'zod';
import { serversMap } from '~/env';
import { liteProvider } from '~/oauth';
import { generateRandomPokemon } from '~/utils/generate';

// The lite provider of the package: no cookies, no encryption, no login. It only verifies plain app tokens and gets them.

const zAvailableServers = z.enum(['express', 'nestjs', 'fastify']);

const zGetB2BInfoBody = z.object({ app: zAvailableServers });

const zB2BResponse = z.object({
  pokemon: z.string().trim().min(1).max(32),
  server: zAvailableServers,
});

export const liteRouter = new Hono();

liteRouter.get('/b2b-info', async (c) => {
  const header = c.req.header('authorization');
  const token = header?.startsWith('Bearer ') ? header.slice('Bearer '.length) : undefined;

  const { meta, error } = await liteProvider.$verifyJwt(token);
  if (error) throw new OAuthError(error);
  if (meta.isApp === false) throw new HTTPException(401, { message: 'Unauthorized' });

  return c.json({ pokemon: generateRandomPokemon(), server: 'honojs', meta });
});

liteRouter.post('/get-b2b-info', zValidator('json', zGetB2BInfoBody), async (c) => {
  const body = c.req.valid('json');

  const { result, error } = await liteProvider.tryGetB2BToken({ app: body.app });
  if (error) throw new OAuthError(error);

  const axiosResponse = await axios.get(`${serversMap[body.app]}/lite/b2b-info`, {
    headers: { Authorization: `Bearer ${result.token}` },
  });
  const { data: b2bRes, error: b2bResError } = zB2BResponse.safeParse(axiosResponse.data);
  if (b2bResError) throw new HTTPException(500, { message: 'Invalid response from B2B server' });

  return c.json({ ...b2bRes, isCached: result.isCached, expiresAt: result.expiresAt });
});
