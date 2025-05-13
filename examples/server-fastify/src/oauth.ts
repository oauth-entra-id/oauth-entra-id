import { OAuthProvider } from 'oauth-entra-id';
import { env } from './env';

export const oauthProvider = new OAuthProvider({
  azure: {
    clientId: env.RED_AZURE_CLIENT_ID,
    tenantId: env.RED_AZURE_TENANT_ID,
    scopes: [env.RED_AZURE_CLIENT_SCOPE],
    clientSecret: env.RED_AZURE_CLIENT_SECRET,
  },
  serverCallbackUrl: `${env.SERVER_URL}/auth/callback`,
  frontendUrl: env.REACT_FRONTEND_URL,
  secretKey: env.RED_SECRET_KEY,
  advanced: {
    onBehalfOfServices: [
      {
        serviceName: 'blue',
        scope: env.BLUE_AZURE_CLIENT_EXPOSED_SCOPE,
        secretKey: env.BLUE_SECRET_KEY,
        isHttps: env.NODE_ENV !== 'development',
        isSameSite: env.NODE_ENV !== 'development',
      },
      {
        serviceName: 'yellow',
        scope: env.YELLOW_AZURE_CLIENT_EXPOSED_SCOPE,
        secretKey: env.YELLOW_SECRET_KEY,
        isHttps: env.NODE_ENV !== 'development',
        isSameSite: env.NODE_ENV !== 'development',
      },
    ],
  },
});
