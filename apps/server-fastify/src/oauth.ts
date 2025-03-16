import { OAuthProvider } from 'oauth-entra-id';
import { AZURE, FASTIFY_FRONTEND_URL, FASTIFY_SECRET, FASTIFY_URL } from './env';

export const oauthProvider = new OAuthProvider({
  azure: AZURE,
  serverFullCallbackUrl: `${FASTIFY_URL}/auth/callback`,
  frontendUrl: FASTIFY_FRONTEND_URL,
  secretKey: FASTIFY_SECRET,
  cookieTimeFrame: 'sec',
});
