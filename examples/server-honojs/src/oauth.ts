import { OAuthProvider } from 'oauth-entra-id';
import { env } from './env';

export const oauthProvider = new OAuthProvider({
  azure: {
    clientId: env.BLUE_AZURE_CLIENT_ID,
    tenantId: env.BLUE_AZURE_TENANT_ID,
    scopes: [env.BLUE_AZURE_CUSTOM_SCOPE],
    clientSecret: env.BLUE_AZURE_CLIENT_SECRET,
  },
  frontendUrl: env.REACT_FRONTEND_URL,
  serverCallbackUrl: `${env.SERVER_URL}/auth/callback`,
  secretKey: env.BLUE_SECRET_KEY,
  advanced: {
    onBehalfOf: {
      isHttps: env.NODE_ENV !== 'development',
      isSameSite: env.NODE_ENV !== 'development',
      services: [
        {
          serviceName: 'red',
          scope: env.RED_AZURE_EXPOSED_SCOPE,
          secretKey: env.RED_SECRET_KEY,
        },
        {
          serviceName: 'yellow',
          scope: env.YELLOW_AZURE_EXPOSED_SCOPE,
          secretKey: env.YELLOW_SECRET_KEY,
        },
      ],
    },
  },
});
