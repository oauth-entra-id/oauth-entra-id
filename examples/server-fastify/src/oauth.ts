import { OAuthProvider } from 'oauth-entra-id';
import { env } from './env';

export const oauthProvider = new OAuthProvider({
  azure: {
    clientId: env.RED_AZURE_CLIENT_ID,
    tenantId: env.RED_AZURE_TENANT_ID,
    scopes: [env.RED_AZURE_CUSTOM_SCOPE],
    clientSecret: env.RED_AZURE_CLIENT_SECRET,
  },
  serverCallbackUrl: `${env.SERVER_URL}/auth/callback`,
  frontendUrl: env.REACT_FRONTEND_URL,
  secretKey: env.RED_SECRET_KEY,
  advanced: {
    b2b: {
      allowB2B: true,
      b2bServices: [
        { b2bServiceName: 'express', b2bScope: env.YELLOW_AZURE_EXPOSED_SCOPE },
        { b2bServiceName: 'nestjs', b2bScope: env.RED_AZURE_EXPOSED_SCOPE },
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
          oboServiceName: 'yellow',
          oboScope: env.YELLOW_AZURE_EXPOSED_SCOPE,
          secretKey: env.YELLOW_SECRET_KEY,
        },
      ],
    },
  },
});
