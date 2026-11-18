import { HttpException, Injectable } from '@nestjs/common';
import axios from 'axios';
import z from 'zod';
import { serversMap } from '~/env';
import { mobileOAuthProvider } from '~/oauth';

const zB2BResponse = z.object({
  pokemon: z.string().trim().min(1).max(32),
  server: z.enum(['express', 'fastify', 'honojs']),
});

@Injectable()
export class MobileService {
  async fetchB2BInfo(app: string, azureId: string | undefined) {
    const { result, error } = await mobileOAuthProvider.tryGetB2BToken({ app, azureId });
    if (error) throw new HttpException('Failed to get B2B token', 500);

    const axiosResponse = await axios.get(`${serversMap[app as keyof typeof serversMap]}/protected/b2b-info`, {
      headers: { Authorization: `Bearer ${result.token}` },
    });

    const { data: b2bRes, error: b2bResError } = zB2BResponse.safeParse(axiosResponse.data);
    if (b2bResError) throw new HttpException('Invalid B2B response', 500);

    return b2bRes;
  }
}
