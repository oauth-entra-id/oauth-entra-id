import type { FastifyInstance } from 'fastify';
import { oauthProvider } from '../oauth';
import protectRoute from '../middlewares/require-authentication';

const route = async (app: FastifyInstance) => {
  app.get('/', () => {
    return { message: 'Hello World' };
  });

  app.get('/health', (req, reply) => {
    reply.status(200).send('OK');
  });

  app.post('/auth/authenticate', async (req, reply) => {
    const body =
      (req.body as
        | {
            loginPrompt?: 'email' | 'select-account' | 'sso';
            email?: string;
            frontendUrl?: string;
          }
        | undefined) || {};

    const { authUrl } = await oauthProvider.generateAuthUrl({
      loginPrompt: body.loginPrompt,
      email: body.email,
      frontendUrl: body.frontendUrl,
    });

    reply.status(200).send({ url: authUrl });
  });

  app.post('/auth/callback', async (req, reply) => {
    const { code, state } = req.body as { code: string; state: string };

    const { frontendUrl, accessToken, refreshToken } = await oauthProvider.exchangeCodeForToken({
      code,
      state,
    });

    reply.setCookie(accessToken.name, accessToken.value, accessToken.options);
    if (refreshToken) reply.setCookie(refreshToken.name, refreshToken.value, refreshToken.options);
    reply.redirect(frontendUrl);
  });

  app.post('/auth/logout', (req, reply) => {
    const body = (req.body as { frontendUrl?: string } | undefined) || {};

    const { logoutUrl, accessToken, refreshToken } = oauthProvider.getLogoutUrl({
      frontendUrl: body.frontendUrl,
    });

    reply.setCookie(accessToken.name, accessToken.value, accessToken.options);
    reply.setCookie(refreshToken.name, refreshToken.value, refreshToken.options);
    reply.status(200).send({ url: logoutUrl });
  });

  app.get('/protected/user-info', { preHandler: protectRoute }, (req) => {
    return { user: req.userInfo };
  });
};

export default route;
