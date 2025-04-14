import { Elysia, t } from 'elysia';
import { oauthProvider } from '~/oauth';

export const authRouter = new Elysia({ prefix: '/auth' });

authRouter.post('/authenticate', async () => {
  //TODO: add json
  const { authUrl } = await oauthProvider.generateAuthUrl();
  return { url: authUrl };
});

authRouter.post('/callback', async ({ request, cookie, set }) => {
  const raw = await request.text();
  const form = Object.fromEntries(new URLSearchParams(raw));
  const { code, state } = form as { code: string; state: string };

  const { frontendUrl, accessToken, refreshToken } = await oauthProvider.exchangeCodeForToken({
    code,
    state,
  });

  const accessTokenName = accessToken.name;
  const refreshTokenName = refreshToken?.name as string;

  cookie[refreshTokenName]?.set({ value: refreshToken?.value, ...refreshToken?.options });
  cookie[accessTokenName]?.set({ value: accessToken.value, ...accessToken.options });

  set.status = 302;

  //! A workaround for the redirect issue in Elysia
  return new Response(null, {
    status: 302,
    headers: {
      location: frontendUrl,
    },
  });
});
