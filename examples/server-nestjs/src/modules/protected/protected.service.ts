import { HttpException, Injectable } from '@nestjs/common';
import axios from 'axios';
import { nestjsOAuthProvider } from 'oauth-entra-id/nestjs';
import z from 'zod/v4';
import { serversMap } from '~/env';

const zB2BResponse = z.object({
  pokemon: z.string().trim().min(1).max(32),
  server: z.enum(['express', 'fastify', 'honojs']),
});

@Injectable()
export class ProtectedService {
  async fetchB2BInfo(app: string) {
    const { result, error } = await nestjsOAuthProvider.tryGetB2BToken({ app: app });
    if (error) throw new HttpException('Failed to get B2B token', 500);

    const serverUrl = serversMap[app];
    const axiosResponse = await axios.get(`${serverUrl}/protected/b2b-info`, {
      headers: { Authorization: `Bearer ${result.token}` },
    });

    const { data: b2bRes, error: b2bResError } = zB2BResponse.safeParse(axiosResponse.data);
    if (b2bResError) throw new HttpException('Invalid B2B response', 500);

    return b2bRes;
  }
}
