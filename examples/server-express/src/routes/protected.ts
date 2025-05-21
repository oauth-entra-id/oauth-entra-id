import axios from 'axios';
import express, { type Router } from 'express';
import { handleOnBehalfOf } from 'oauth-entra-id/express';
import { z } from 'zod';
import { env } from '~/env';
import { HttpException } from '~/error/HttpException';

const zAvailableServers = z.enum(['nestjs', 'fastify', 'honojs']);

const zGetB2BInfoBody = z.object({
  appName: zAvailableServers,
});

export const protectedRouter: Router = express.Router();

protectedRouter.get('/user-info', (req, res) => {
  res.status(200).json({ user: req.userInfo });
});

protectedRouter.post('/on-behalf-of', handleOnBehalfOf);

protectedRouter.post('/get-b2b-info', async (req, res) => {
  const { data: body, error: bodyError } = zGetB2BInfoBody.safeParse(req.body);
  if (bodyError) throw new HttpException('Invalid params', 400);

  const { accessToken } = await req.oauthProvider.getB2BToken({ appName: body.appName });
  const serverUrl = serversMap[body.appName];
  const axiosResponse = await axios.get(`${serverUrl}/protected/b2b-info`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  const { data, error } = zB2BResponse.safeParse(axiosResponse.data);
  if (error) throw new HttpException('Invalid B2B response', 500);
  res.status(200).json(data);
});

protectedRouter.get('/b2b-info', (req, res) => {
  if (req.userInfo?.isB2B === false) throw new HttpException('Unauthorized', 401);
  const randomPokemon = pokemon[Math.floor(Math.random() * pokemon.length)];
  res.status(200).json({ pokemon: randomPokemon, server: 'express' });
});

const zB2BResponse = z.object({
  pokemon: z.string().trim().min(1).max(32),
  server: zAvailableServers,
});

const serversMap = {
  nestjs: env.NESTJS_URL,
  fastify: env.FASTIFY_URL,
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
