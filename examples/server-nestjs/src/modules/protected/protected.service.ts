import { HttpException, Injectable } from '@nestjs/common';
import axios from 'axios';
import type { OAuthProvider } from 'oauth-entra-id';
import z from 'zod';
import { env } from '~/env';

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

@Injectable()
export class ProtectedService {
  async fetchB2BInfo(oauthProvider: OAuthProvider, appName: string) {
    const { accessToken } = await oauthProvider.getB2BToken({ appName });
    const serverUrl = serversMap[appName];
    const axiosResponse = await axios.get(`${serverUrl}/protected/b2b-info`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    const { data, error } = zB2BResponse.safeParse(axiosResponse.data);
    if (error) throw new HttpException('Invalid B2B response', 500);
    return data;
  }

  generateRandomPokemon() {
    return pokemon[Math.floor(Math.random() * pokemon.length)];
  }
}
