import { OAuthProvider } from 'oauth-entra-id';
import { AZURE, REACT_FRONTEND_URL, SECRET_KEY, FASTIFY_URL } from './env';

export const oauthProvider = new OAuthProvider({
  azure: AZURE,
  serverFullCallbackUrl: `${FASTIFY_URL}/auth/callback`,
  frontendUrl: REACT_FRONTEND_URL,
  secretKey: SECRET_KEY,
  cookieTimeFrame: 'sec',
});
