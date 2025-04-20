import { OAuthProvider } from 'oauth-entra-id';
import { env } from './env';

export const oauthProvider = new OAuthProvider({
  azure: env.AZURE,
  frontendUrl: env.REACT_FRONTEND_URL,
  serverCallbackUrl: `${env.SERVER_URL}/auth/callback`,
  secretKey: env.SECRET_KEY,
  advanced: {
    cookieTimeFrame: 'sec',
    debug: true,
    onBehalfOfOptions: {
      serviceName: 'main',
      scopes: env.AZURE2.scopes,
      secretKey: env.SECRET_KEY,
      isHttps: env.NODE_ENV !== 'development',
      isSameSite: env.NODE_ENV !== 'development',
    },
  },
});
