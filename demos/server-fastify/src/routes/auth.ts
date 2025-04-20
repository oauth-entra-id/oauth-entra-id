import type { FastifyInstance } from 'fastify';
import { oauthProvider } from '~/oauth';

export const authRouter = async (app: FastifyInstance) => {
  app.post('/authenticate', async (req, reply) => {
    const body =
      (req.body as
        | {
            loginPrompt?: 'email' | 'select-account' | 'sso';
            email?: string;
            frontendUrl?: string;
          }
        | undefined) || {};

    const { url } = await oauthProvider.getAuthUrl({
      loginPrompt: body.loginPrompt,
      email: body.email,
      frontendUrl: body.frontendUrl,
    });

    reply.status(200).send({ url });
  });

  app.post('/callback', async (req, reply) => {
    const { code, state } = req.body as { code: string; state: string };

    const { url, accessToken, refreshToken } = await oauthProvider.getTokenByCode({
      code,
      state,
    });

    reply.setCookie(accessToken.name, accessToken.value, accessToken.options);
    if (refreshToken) reply.setCookie(refreshToken.name, refreshToken.value, refreshToken.options);
    reply.redirect(url);
  });

  app.post('/logout', (req, reply) => {
    const body = (req.body as { frontendUrl?: string } | undefined) || {};

    const { url, accessToken, refreshToken } = oauthProvider.getLogoutUrl({
      frontendUrl: body.frontendUrl,
    });

    reply.setCookie(accessToken.name, accessToken.value, accessToken.options);
    reply.setCookie(refreshToken.name, refreshToken.value, refreshToken.options);
    reply.status(200).send({ url });
  });
};
