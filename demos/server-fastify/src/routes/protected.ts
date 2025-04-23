import type { FastifyInstance } from 'fastify';
import protectRoute from '~/middlewares/require-authentication';
import { oauthProvider } from '~/oauth';

export const protectedRouter = async (app: FastifyInstance) => {
  app.addHook('preHandler', protectRoute);

  app.get('/user-info', (req, reply) => {
    return { user: req.userInfo };
  });

  app.post('/on-behalf-of', async (req, reply) => {
    const { serviceNames } = (req.body as { serviceNames: string[] }) || {};

    const results = await oauthProvider.getTokenOnBehalfOf({
      accessToken: req.msal.microsoftToken,
      serviceNames,
    });

    for (const result of results) {
      const { accessToken, refreshToken } = result;
      reply.setCookie(accessToken.name, accessToken.value, accessToken.options);
      if (refreshToken) reply.setCookie(refreshToken.name, refreshToken.value, refreshToken.options);
    }

    return { tokensSet: results.length };
  });
};
