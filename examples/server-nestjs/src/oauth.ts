import type { OAuthConfig } from 'oauth-entra-id';
import { env } from './env';

//! RED SERVICE
export const oauthConfig = {
  azure: {
    clientId: env.AZURE_RED_CLIENT_ID,
    tenantId: env.AZURE_RED_TENANT_ID,
    scopes: [env.AZURE_RED_CUSTOM_SCOPE],
    clientSecret: env.AZURE_RED_CLIENT_SECRET,
  },
  frontendUrl: env.REACT_FRONTEND_URL,
  serverCallbackUrl: `${env.SERVER_URL}/auth/callback`,
  secretKey: env.RED_SECRET_KEY,
  advanced: {
    acceptB2BRequests: true,
    b2bTargetedApps: [
      { appName: 'express', scope: env.AZURE_YELLOW_EXPOSED_SCOPE },
      { appName: 'fastify', scope: env.AZURE_RED_EXPOSED_SCOPE },
      { appName: 'honojs', scope: env.AZURE_BLUE_EXPOSED_SCOPE },
    ],
    downstreamServices: {
      areHttps: env.NODE_ENV !== 'development',
      areSameOrigin: env.NODE_ENV !== 'development',
      services: [
        {
          clientId: env.AZURE_YELLOW_CLIENT_ID,
          scope: env.AZURE_YELLOW_EXPOSED_SCOPE,
          secretKey: env.YELLOW_SECRET_KEY,
        },
        {
          clientId: env.AZURE_BLUE_CLIENT_ID,
          scope: env.AZURE_BLUE_EXPOSED_SCOPE,
          secretKey: env.BLUE_SECRET_KEY,
        },
      ],
    },
  },
} satisfies OAuthConfig;
