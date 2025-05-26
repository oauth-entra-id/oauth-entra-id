import { OAuthProvider } from 'oauth-entra-id';
import { env } from './env';

//! RED SERVICE
export const oauthProvider = new OAuthProvider({
  azure: {
    clientId: env.AZURE_RED_CLIENT_ID,
    tenantId: env.AZURE_RED_TENANT_ID,
    scopes: [env.AZURE_RED_CUSTOM_SCOPE],
    clientSecret: env.AZURE_RED_CLIENT_SECRET,
  },
  serverCallbackUrl: `${env.SERVER_URL}/auth/callback`,
  frontendUrl: env.REACT_FRONTEND_URL,
  secretKey: env.RED_SECRET_KEY,
  advanced: {
    acceptB2BRequests: true,
    b2bTargetedApps: [
      { appName: 'express', scope: env.AZURE_YELLOW_EXPOSED_SCOPE },
      { appName: 'nestjs', scope: env.AZURE_RED_EXPOSED_SCOPE },
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
          serviceName: 'yellow',
          scope: env.AZURE_YELLOW_EXPOSED_SCOPE,
          secretKey: env.YELLOW_SECRET_KEY,
        },
      ],
    },
  },
});
