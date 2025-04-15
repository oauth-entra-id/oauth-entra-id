import { OAuthProvider } from 'oauth-entra-id';
import { env } from './env';

export const oauthProvider = new OAuthProvider({
  azure: env.AZURE,
  serverCallbackUrl: `${env.SERVER_URL}/auth/callback`,
  frontendUrl: env.REACT_FRONTEND_URL,
  secretKey: env.SECRET_KEY,
  advanced: { cookieTimeFrame: 'sec' },
});
