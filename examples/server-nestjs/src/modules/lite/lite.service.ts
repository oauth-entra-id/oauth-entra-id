import { HttpException, Injectable } from '@nestjs/common';
import axios from 'axios';
import { OAuthError } from 'oauth-entra-id';
import z from 'zod';
import { serversMap } from '~/env';
import { liteProvider } from '~/oauth';

const zB2BResponse = z.object({
  pokemon: z.string().trim().min(1).max(32),
  server: z.enum(['express', 'fastify', 'honojs']),
});

@Injectable()
export class LiteService {
  async fetchB2BInfo(app: string) {
    const { result, error } = await liteProvider.tryGetB2BToken({ app });
    if (error) throw new OAuthError(error);

    const axiosResponse = await axios.get(`${serversMap[app]}/lite/b2b-info`, {
      headers: { Authorization: `Bearer ${result.token}` },
    });

    const { data: b2bRes, error: b2bResError } = zB2BResponse.safeParse(axiosResponse.data);
    if (b2bResError) throw new HttpException('Invalid B2B response', 500);

    return { ...b2bRes, isCached: result.isCached, expiresAt: result.expiresAt };
  }
}
