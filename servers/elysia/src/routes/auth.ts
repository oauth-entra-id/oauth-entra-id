import { Elysia, t } from 'elysia';
import { oauthProvider } from '~/oauth';

export const authRouter = new Elysia({ prefix: '/auth' });

authRouter.post('/authenticate', async () => {
  //TODO: add json
  const { authUrl } = await oauthProvider.generateAuthUrl();
  return { url: authUrl };
});

// authRouter.post('/callback', async ({ request, cookie, redirect }) => {
//   const raw = await request.text();
//   const form = Object.fromEntries(new URLSearchParams(raw));
//   const { code, state } = form as { code: string; state: string };

//   const { frontendUrl, accessToken, refreshToken } = await oauthProvider.exchangeCodeForToken({
//     code,
//     state,
//   });

//     cookie[accessToken.name]?.set({ value: accessToken.value, ...accessToken.options });

//     if (refreshToken) {
//       cookie[refreshToken.name]?.set({ value: refreshToken.value, ...refreshToken.options });
//     }
//   return redirect(frontendUrl);
// });
