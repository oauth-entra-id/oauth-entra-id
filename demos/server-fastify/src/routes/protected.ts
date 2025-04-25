import type { FastifyPluginAsyncTypebox } from '@fastify/type-provider-typebox';
import { Type as t } from '@sinclair/typebox';
import protectRoute from '~/middlewares/require-authentication';
import { oauthProvider } from '~/oauth';

const tSchemas = {
  onBehalfOf: t.Object({
    serviceNames: t.Array(t.String(), { minItems: 1 }),
  }),
};

export const protectedRouter: FastifyPluginAsyncTypebox = async (app) => {
  app.addHook('preHandler', protectRoute);

  app.get('/user-info', (req, reply) => {
    return { user: req.userInfo };
  });

  app.post('/on-behalf-of', { schema: { body: tSchemas.onBehalfOf } }, async (req, reply) => {
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
