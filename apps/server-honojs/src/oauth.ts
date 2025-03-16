import { OAuthProvider } from 'oauth-entra-id';
import { AZURE, HONOJS_FRONTEND_URL, HONOJS_SECRET, HONOJS_URL } from './env';

export const oauthProvider = new OAuthProvider({
  azure: AZURE,
  frontendUrl: HONOJS_FRONTEND_URL,
  serverFullCallbackUrl: `${HONOJS_URL}/auth/callback`,
  secretKey: HONOJS_SECRET,
  cookieTimeFrame: 'sec',
  debug: true,
});
