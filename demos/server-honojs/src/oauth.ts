import { OAuthProvider } from 'oauth-entra-id';
import { env } from './env';

export const oauthProvider = new OAuthProvider({
  azure: env.AZURE_BLUE,
  frontendUrl: env.REACT_FRONTEND_URL,
  serverCallbackUrl: `${env.SERVER_URL}/auth/callback`,
  secretKey: env.SECRET_KEY_BLUE,
  advanced: {
    cookieTimeFrame: 'sec',
    debug: true,
    onBehalfOfOptions: [
      {
        serviceName: 'red',
        scopes: env.AZURE_RED.scopes,
        secretKey: env.SECRET_KEY_RED,
        isHttps: env.NODE_ENV !== 'development',
        isSameSite: env.NODE_ENV !== 'development',
      },
      {
        serviceName: 'yellow',
        scopes: env.AZURE_YELLOW.scopes,
        secretKey: env.SECRET_KEY_YELLOW,
        isHttps: env.NODE_ENV !== 'development',
        isSameSite: env.NODE_ENV !== 'development',
      },
    ],
  },
});
