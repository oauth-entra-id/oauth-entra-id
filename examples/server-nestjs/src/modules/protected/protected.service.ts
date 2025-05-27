import { HttpException, Injectable } from '@nestjs/common';
import axios from 'axios';
import type { OAuthProvider } from 'oauth-entra-id';
import z from 'zod';
import { env } from '~/env';

@Injectable()
export class ProtectedService {
  async fetchB2BInfo(oauthProvider: OAuthProvider, appName: string) {
    const { result, error } = await oauthProvider.getB2BToken({ appName });
    if (error) throw new HttpException(error.message, error.statusCode);
    const { accessToken } = result;

    const serverUrl = serversMap[appName];
    const axiosResponse = await axios.get(`${serverUrl}/protected/b2b-info`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    const { data: b2bRes, error: b2bResError } = zB2BResponse.safeParse(axiosResponse.data);
    if (b2bResError) throw new HttpException('Invalid B2B response', 500);
    return b2bRes;
  }

  generateRandomPokemon() {
    return pokemon[Math.floor(Math.random() * pokemon.length)];
  }
}

const zB2BResponse = z.object({
  pokemon: z.string().trim().min(1).max(32),
  server: z.enum(['express', 'fastify', 'honojs']),
});

const serversMap = {
  express: env.EXPRESS_URL,
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
