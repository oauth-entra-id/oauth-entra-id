import type { FastifyPluginAsyncTypebox } from '@fastify/type-provider-typebox';
import { Type as t } from '@sinclair/typebox';
import protectRoute from '~/middlewares/protect-route';
import { oauthProvider } from '~/oauth';

const tSchemas = {
  onBehalfOf: t.Object({
    oboServiceNames: t.Array(t.String(), { minItems: 1 }),
  }),
};

export const protectedRouter: FastifyPluginAsyncTypebox = async (app) => {
  app.addHook('preHandler', protectRoute);

  app.get('/user-info', (req, reply) => {
    return { user: req.userInfo };
  });

  app.post('/on-behalf-of', { schema: { body: tSchemas.onBehalfOf } }, async (req, reply) => {
    const { oboServiceNames } = req.body || {};

    const results = await oauthProvider.getTokenOnBehalfOf({
      accessToken: req.microsoftInfo.rawAccessToken,
      oboServiceNames,
    });

    for (const result of results) {
      const { oboAccessToken, oboRefreshToken } = result;
      reply.setCookie(oboAccessToken.name, oboAccessToken.value, oboAccessToken.options);
      if (oboRefreshToken) reply.setCookie(oboRefreshToken.name, oboRefreshToken.value, oboRefreshToken.options);
    }

    return { tokensSet: results.length };
  });
};
