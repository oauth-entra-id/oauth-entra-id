import type { OAuthConfig } from 'oauth-entra-id';
import { env } from './env';

export const oauthConfig = {
  azure: {
    clientId: env.YELLOW_AZURE_CLIENT_ID,
    tenantId: env.YELLOW_AZURE_TENANT_ID,
    scopes: [env.YELLOW_AZURE_CUSTOM_SCOPE],
    clientSecret: env.YELLOW_AZURE_CLIENT_SECRET,
  },
  frontendUrl: env.REACT_FRONTEND_URL,
  serverCallbackUrl: `${env.SERVER_URL}/auth/callback`,
  secretKey: env.YELLOW_SECRET_KEY,
  advanced: {
    b2b: {
      allowB2B: true,
      b2bServices: [
        { b2bServiceName: 'nestjs', b2bScope: env.RED_AZURE_EXPOSED_SCOPE },
        { b2bServiceName: 'fastify', b2bScope: env.RED_AZURE_EXPOSED_SCOPE },
        { b2bServiceName: 'honojs', b2bScope: env.BLUE_AZURE_EXPOSED_SCOPE },
      ],
    },
    onBehalfOf: {
      isHttps: env.NODE_ENV !== 'development',
      isSameSite: env.NODE_ENV !== 'development',
      oboServices: [
        {
          oboServiceName: 'blue',
          oboScope: env.BLUE_AZURE_EXPOSED_SCOPE,
          secretKey: env.BLUE_SECRET_KEY,
        },
        {
          oboServiceName: 'red',
          oboScope: env.RED_AZURE_EXPOSED_SCOPE,
          secretKey: env.RED_SECRET_KEY,
        },
      ],
    },
  },
} satisfies OAuthConfig;
