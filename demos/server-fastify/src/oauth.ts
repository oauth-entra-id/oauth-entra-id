import { OAuthProvider } from 'oauth-entra-id';
import { env } from './env';

export const oauthProvider = new OAuthProvider({
  azure: {
    clientId: env.RED_AZURE_CLIENT_ID,
    tenantId: env.RED_AZURE_TENANT_ID,
    scopes: [env.RED_AZURE_CLIENT_SCOPE],
    secret: env.RED_AZURE_CLIENT_SECRET,
  },
  serverCallbackUrl: `${env.SERVER_URL}/auth/callback`,
  frontendUrl: env.REACT_FRONTEND_URL,
  secretKey: env.RED_SECRET_KEY,
  advanced: { cookieTimeFrame: 'sec' },
});
