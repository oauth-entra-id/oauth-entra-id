import type { OAuthConfig } from 'oauth-entra-id';
import { env } from './env';

//! YELLOW SERVICE
export const oauthConfig = {
  azure: {
    clientId: env.AZURE_YELLOW_CLIENT_ID,
    tenantId: env.AZURE_YELLOW_TENANT_ID,
    scopes: [env.AZURE_YELLOW_CUSTOM_SCOPE],
    clientSecret: env.AZURE_YELLOW_CLIENT_SECRET,
  },
  frontendUrl: env.REACT_FRONTEND_URL,
  serverCallbackUrl: `${env.SERVER_URL}/auth/callback`,
  secretKey: env.YELLOW_SECRET_KEY,
  advanced: {
    cryptoType: 'web-api',
    acceptB2BRequests: true,
    b2bTargetedApps: [
      { appName: 'nestjs', scope: env.AZURE_RED_EXPOSED_SCOPE },
      { appName: 'fastify', scope: env.AZURE_RED_EXPOSED_SCOPE },
      { appName: 'honojs', scope: env.AZURE_BLUE_EXPOSED_SCOPE },
    ],
    downstreamServices: {
      areHttps: env.NODE_ENV !== 'development',
      areSameOrigin: env.NODE_ENV !== 'development',
      services: [
        {
          serviceName: 'blue',
          scope: env.AZURE_BLUE_EXPOSED_SCOPE,
          secretKey: env.BLUE_SECRET_KEY,
        },
        {
          serviceName: 'red',
          scope: env.AZURE_RED_EXPOSED_SCOPE,
          secretKey: env.RED_SECRET_KEY,
        },
      ],
    },
  },
} satisfies OAuthConfig;
