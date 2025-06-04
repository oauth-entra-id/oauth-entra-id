import { OAuthProvider } from 'oauth-entra-id';
import { env } from './env';

//! BLUE SERVICE
export const oauthProvider = new OAuthProvider({
  azure: {
    clientId: env.AZURE_BLUE_CLIENT_ID,
    tenantId: env.AZURE_BLUE_TENANT_ID,
    scopes: [env.AZURE_BLUE_CUSTOM_SCOPE],
    clientSecret: env.AZURE_BLUE_CLIENT_SECRET,
  },
  frontendUrl: env.REACT_FRONTEND_URL,
  serverCallbackUrl: `${env.SERVER_URL}/auth/callback`,
  secretKey: env.BLUE_SECRET_KEY,
  advanced: {
    acceptB2BRequests: true,
    b2bTargetedApps: [
      { appName: 'express', scope: env.AZURE_YELLOW_EXPOSED_SCOPE },
      { appName: 'nestjs', scope: env.AZURE_RED_EXPOSED_SCOPE },
      { appName: 'fastify', scope: env.AZURE_RED_EXPOSED_SCOPE },
    ],
    downstreamServices: {
      areHttps: env.NODE_ENV !== 'development',
      areSameOrigin: env.NODE_ENV !== 'development',
      services: [
        {
          serviceName: 'yellow',
          scope: env.AZURE_YELLOW_EXPOSED_SCOPE,
          secretKey: env.YELLOW_SECRET_KEY,
          cryptoType: 'web-api',
        },
        {
          serviceName: 'red',
          scope: env.AZURE_RED_EXPOSED_SCOPE,
          secretKey: env.RED_SECRET_KEY,
        },
      ],
    },
  },
});
