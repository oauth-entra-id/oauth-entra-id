import type { APIRequestContext, APIResponse } from '@playwright/test';
import { type Color, liveEnv, type ServerName } from './env';

const env = liveEnv();

export interface Tokens {
  accessToken: string;
  refreshToken: string;
}

export function looksLikeJwt(value: string): boolean {
  return /^eyJ[\w-]+\.[\w-]+\./.test(value);
}

export function tamper(value: string): string {
  const at = Math.floor(value.length / 2);
  return `${value.slice(0, at)}${value[at] === 'A' ? 'B' : 'A'}${value.slice(at + 1)}`;
}

/** The mobile app talking to one server: plain HTTP, tokens are passed in by hand, nothing is remembered between calls. */
export class MobileApi {
  constructor(
    private readonly request: APIRequestContext,
    readonly server: ServerName,
  ) {}

  private get url(): string {
    return env.servers[this.server].url;
  }

  login(body: Record<string, unknown> = {}): Promise<APIResponse> {
    return this.request.post(`${this.url}/auth/mobile/login`, { data: body });
  }

  exchange(body: Record<string, unknown>): Promise<APIResponse> {
    return this.request.post(`${this.url}/auth/mobile/token`, { data: body });
  }

  refresh(body: Record<string, unknown>): Promise<APIResponse> {
    return this.request.post(`${this.url}/auth/mobile/refresh`, { data: body });
  }

  userInfo(accessToken?: string): Promise<APIResponse> {
    const headers: Record<string, string> = accessToken === undefined ? {} : { Authorization: `Bearer ${accessToken}` };
    return this.request.get(`${this.url}/protected/mobile/user-info`, { headers });
  }

  async newLogin(body: Record<string, unknown> = {}): Promise<{ url: URL; ticket: string }> {
    const response = await this.login(body);
    const { url, ticket } = (await response.json()) as { url: string; ticket: string };
    return { url: new URL(url), ticket };
  }

  async refreshTokens(refreshToken: string): Promise<Tokens> {
    const response = await this.refresh({ refreshToken });
    return (await response.json()) as Tokens;
  }
}

/**
 * A real app (client credentials) token of one registration for another one, the kind a server sends to a B2B service.
 * It is requested straight from Entra ID with the secrets of the test registrations.
 */
export async function fetchAppToken(request: APIRequestContext, from: Color, to: Color): Promise<string> {
  const prefix = `${from.toUpperCase()}1_AZURE`;
  const response = await request.post(
    `https://login.microsoftonline.com/${env.apps[from].tenantId}/oauth2/v2.0/token`,
    {
      form: {
        grant_type: 'client_credentials',
        client_id: env.apps[from].clientId,
        client_secret: process.env[`${prefix}_CLIENT_SECRET`] ?? '',
        scope: process.env[`${to.toUpperCase()}1_AZURE_EXPOSED_SCOPE`] ?? '',
      },
    },
  );
  if (!response.ok())
    throw new Error(`Entra ID did not give a ${from} app token for ${to} (status ${response.status()})`);
  return ((await response.json()) as { access_token: string }).access_token;
}
