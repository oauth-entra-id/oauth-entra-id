import { zValidator } from '@hono/zod-validator';
import axios from 'axios';
import { Hono } from 'hono';
import { setCookie } from 'hono/cookie';
import { HTTPException } from 'hono/http-exception';
import { z } from 'zod';
import { env } from '~/env';
import { type ProtectRoute, protectRoute } from '~/middlewares/protect-route';
import { oauthProvider } from '~/oauth';

const zAvailableServers = z.enum(['express', 'nestjs', 'fastify']);

const zSchemas = {
  onBehalfOf: z.object({
    serviceNames: z.array(z.string()),
  }),
  getB2BInfo: z.object({
    appName: zAvailableServers,
  }),
};

export const protectedRouter = new Hono<ProtectRoute>();

protectedRouter.use(protectRoute);

protectedRouter.get('/user-info', (c) => {
  return c.json({ user: c.get('userInfo') });
});

protectedRouter.post('/on-behalf-of', zValidator('json', zSchemas.onBehalfOf), async (c) => {
  if (c.get('userInfo')?.isApp === true) throw new HTTPException(401, { message: 'B2B users cannot use OBO' });

  const { serviceNames } = c.req.valid('json');
  const { results, error } = await oauthProvider.getTokenOnBehalfOf({
    accessToken: c.get('accessTokenInfo').jwt,
    serviceNames,
  });

  if (error) throw new HTTPException(error.statusCode, { message: error.message });

  for (const { accessToken } of results) {
    setCookie(c, accessToken.name, accessToken.value, accessToken.options);
  }
  return c.json({ tokensSet: results.length });
});

protectedRouter.post('/get-b2b-info', zValidator('json', zSchemas.getB2BInfo), async (c) => {
  const { appName } = c.req.valid('json');
  const { result, error } = await oauthProvider.getB2BToken({ appName });

  if (error) throw new HTTPException(error.statusCode, { message: error.message });
  const { accessToken } = result;

  const serverUrl = serversMap[appName];
  const axiosResponse = await axios.get(`${serverUrl}/protected/b2b-info`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  const { data: b2bRes, error: b2bResError } = zB2BResponse.safeParse(axiosResponse.data);
  if (b2bResError) throw new HTTPException(500, { message: 'Invalid response from B2B server' });
  return c.json(b2bRes);
});

protectedRouter.get('/b2b-info', (c) => {
  if (c.get('userInfo')?.isApp === false) throw new HTTPException(401, { message: 'Unauthorized' });
  const randomPokemon = pokemon[Math.floor(Math.random() * pokemon.length)];
  return c.json({ pokemon: randomPokemon, server: 'honojs' });
});

const zB2BResponse = z.object({
  pokemon: z.string().trim().min(1).max(32),
  server: zAvailableServers,
});

const serversMap = {
  express: env.EXPRESS_URL,
  nestjs: env.NESTJS_URL,
  fastify: env.FASTIFY_URL,
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
