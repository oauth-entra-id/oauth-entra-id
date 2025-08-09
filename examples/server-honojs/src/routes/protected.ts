import { zValidator } from '@hono/zod-validator';
import axios from 'axios';
import { Hono } from 'hono';
import { setCookie } from 'hono/cookie';
import { HTTPException } from 'hono/http-exception';
import { z } from 'zod';
import { serversMap } from '~/env';
import { type ProtectRoute, protectRoute } from '~/middlewares/protect-route';
import { oauthProvider } from '~/oauth';
import { generateRandomPokemon } from '~/utils/generate';

const zAvailableServers = z.enum(['express', 'nestjs', 'fastify']);

const zSchemas = {
  onBehalfOf: z.object({
    services: z.array(z.string()),
    azureId: z.uuid().optional(),
  }),
  getB2BInfo: z.object({
    app: zAvailableServers,
    azureId: z.uuid().optional(),
  }),
};

export const protectedRouter = new Hono<ProtectRoute>();

protectedRouter.use(protectRoute);

protectedRouter.get('/user-info', (c) => {
  return c.json({ user: c.get('userInfo') });
});

protectedRouter.post('/on-behalf-of', zValidator('json', zSchemas.onBehalfOf), async (c) => {
  if (c.get('userInfo')?.isApp === true) throw new HTTPException(401, { message: 'B2B users cannot use OBO' });

  const body = c.req.valid('json');
  const { results } = await oauthProvider.getTokenOnBehalfOf({
    accessToken: c.get('accessTokenInfo').jwt,
    services: body.services,
    azureId: body.azureId,
  });

  for (const { accessToken } of results) {
    setCookie(c, accessToken.name, accessToken.value, accessToken.options);
  }
  return c.json({ tokensSet: results.length });
});

protectedRouter.get('/b2b-info', (c) => {
  if (c.get('userInfo')?.isApp === false) throw new HTTPException(401, { message: 'Unauthorized' });
  return c.json({ pokemon: generateRandomPokemon(), server: 'honojs' });
});

const zB2BResponse = z.object({
  pokemon: z.string().trim().min(1).max(32),
  server: zAvailableServers,
});

protectedRouter.post('/get-b2b-info', zValidator('json', zSchemas.getB2BInfo), async (c) => {
  const body = c.req.valid('json');
  const { result, error } = await oauthProvider.tryGetB2BToken({ app: body.app, azureId: body.azureId });
  if (error) throw new HTTPException(500, { message: 'Failed to get B2B token' });

  const serverUrl = serversMap[body.app];
  const axiosResponse = await axios.get(`${serverUrl}/protected/b2b-info`, {
    headers: { Authorization: `Bearer ${result.token}` },
  });
  const { data: b2bRes, error: b2bResError } = zB2BResponse.safeParse(axiosResponse.data);
  if (b2bResError) throw new HTTPException(500, { message: 'Invalid response from B2B server' });
  return c.json(b2bRes);
});
