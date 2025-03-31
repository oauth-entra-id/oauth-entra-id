import { OAuthProvider } from 'oauth-entra-id';
import { AZURE, REACT_FRONTEND_URL, SECRET_KEY, HONOJS_URL } from './env';

export const oauthProvider = new OAuthProvider({
  azure: AZURE,
  frontendUrl: REACT_FRONTEND_URL,
  serverFullCallbackUrl: `${HONOJS_URL}/auth/callback`,
  secretKey: SECRET_KEY,
  cookieTimeFrame: 'sec',
  debug: true,
});
