import type { OAuthConfig } from 'oauth-entra-id';
import { env } from './env';

//! YELLOW SERVICE
export const oauthConfig = {
  azure: {
    clientId: env.AZURE_YELLOW_CLIENT_ID,
    tenantId: env.AZURE_YELLOW_TENANT_ID,
    scopes: [env.AZURE_YELLOW_CUSTOM_SCOPE],
    clientSecret: env.AZURE_YELLOW_CLIENT_SECRET,
    downstreamServices: [
      {
        serviceName: 'red',
        scope: env.AZURE_RED_EXPOSED_SCOPE,
        serviceUrl: [env.NESTJS_URL, env.FASTIFY_URL],
        encryptionKey: env.RED_SECRET_KEY,
      },
      {
        serviceName: 'blue',
        scope: env.AZURE_BLUE_EXPOSED_SCOPE,
        serviceUrl: env.HONOJS_URL,
        encryptionKey: env.BLUE_SECRET_KEY,
      },
    ],
    b2bApps: [
      { appName: 'fastify', scope: env.AZURE_RED_EXPOSED_SCOPE },
      { appName: 'honojs', scope: env.AZURE_BLUE_EXPOSED_SCOPE },
      { appName: 'nestjs', scope: env.AZURE_RED_EXPOSED_SCOPE },
    ],
  },
  frontendUrl: env.REACT_FRONTEND_URL,
  serverCallbackUrl: `${env.SERVER_URL}/auth/callback`,
  encryptionKey: env.YELLOW_SECRET_KEY,
  advanced: {
    acceptB2BRequests: true,
    cryptoType: 'web-api',
  },
} satisfies OAuthConfig;
