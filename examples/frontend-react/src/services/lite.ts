import axios from 'axios';
import { z } from 'zod';
import { getMobileTokens } from '~/lib/mobile-storage';
import { type Server, useServerStore } from '~/stores/server-store';

// The lite routes work with plain tokens and no cookies. These calls skip `axiosFetch`, because in mobile app mode its
// interceptor would add the signed-in user's token to every request, and "no token" would not be tested.
const liteFetch = axios.create({ withCredentials: false, validateStatus: () => true });

export type LiteToken = 'none' | 'empty' | 'garbage' | 'too-long' | 'login-token';

function authorizationFor(token: LiteToken): string | undefined {
  switch (token) {
    case 'none':
      return undefined;
    case 'empty':
      return 'Bearer ';
    case 'garbage':
      return 'Bearer garbage';
    case 'too-long':
      return `Bearer ${'a'.repeat(5000)}`;
    case 'login-token': {
      const tokens = getMobileTokens();
      return tokens ? `Bearer ${tokens.accessToken}` : undefined;
    }
  }
}

export function hasLoginToken(): boolean {
  return getMobileTokens() !== null;
}

/** Sends a token to the lite route of the current server. A server that does not answer is status 0. */
export async function verifyWithLite(token: LiteToken): Promise<number> {
  const serverUrl = useServerStore.getState().serverUrl;
  const authorization = authorizationFor(token);
  try {
    const res = await liteFetch.get(`${serverUrl}/lite/b2b-info`, {
      headers: authorization === undefined ? {} : { Authorization: authorization },
    });
    return res.status;
  } catch {
    return 0;
  }
}

const zLiteB2BData = z.object({
  pokemon: z.string().trim().min(1).max(32),
  server: z.enum(['express', 'nestjs', 'fastify', 'honojs']),
  isCached: z.boolean(),
  expiresAt: z.number(),
});

export type LiteB2BData = z.infer<typeof zLiteB2BData>;

/** The current server gets an app token with the lite provider and calls the lite route of the other server with it. */
export async function getLiteB2BData(body: { app?: Server | string }): Promise<{ status: number; data?: LiteB2BData }> {
  const serverUrl = useServerStore.getState().serverUrl;
  try {
    const res = await liteFetch.post(`${serverUrl}/lite/get-b2b-info`, body);
    const parsed = zLiteB2BData.safeParse(res.data);
    return { status: res.status, data: res.status === 200 && parsed.success ? parsed.data : undefined };
  } catch {
    return { status: 0 };
  }
}
