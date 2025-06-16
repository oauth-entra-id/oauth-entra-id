import { OAuthProvider } from 'oauth-entra-id';
import { env } from './env';

//! RED SERVICE
export const oauthProvider = new OAuthProvider({
  azure: {
    clientId: env.AZURE_RED_CLIENT_ID,
    tenantId: env.AZURE_RED_TENANT_ID,
    scopes: [env.AZURE_RED_CUSTOM_SCOPE],
    clientSecret: env.AZURE_RED_CLIENT_SECRET,
    downstreamServices: [
      {
        serviceName: 'yellow',
        scope: env.AZURE_YELLOW_EXPOSED_SCOPE,
        serviceUrl: env.EXPRESS_URL,
        encryptionKey: env.YELLOW_SECRET_KEY,
        cryptoType: 'web-api',
      },
      {
        serviceName: 'blue',
        scope: env.AZURE_BLUE_EXPOSED_SCOPE,
        serviceUrl: env.HONOJS_URL,
        encryptionKey: env.BLUE_SECRET_KEY,
      },
    ],
    b2bApps: [
      { appName: 'express', scope: env.AZURE_YELLOW_EXPOSED_SCOPE },
      { appName: 'nestjs', scope: env.AZURE_RED_EXPOSED_SCOPE },
      { appName: 'honojs', scope: env.AZURE_BLUE_EXPOSED_SCOPE },
    ],
  },
  frontendUrl: env.REACT_FRONTEND_URL,
  serverCallbackUrl: `${env.SERVER_URL}/auth/callback`,
  encryptionKey: env.RED_SECRET_KEY,
  advanced: {
    acceptB2BRequests: true,
  },
});
