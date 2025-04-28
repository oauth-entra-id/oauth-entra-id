import type { FastifyPluginAsyncTypebox } from '@fastify/type-provider-typebox';
import { Type as t } from '@sinclair/typebox';
import { oauthProvider } from '~/oauth';

const tSchemas = {
  authenticate: t.Object({
    loginPrompt: t.Optional(t.Union([t.Literal('email'), t.Literal('select-account'), t.Literal('sso')])),
    email: t.Optional(t.String({ format: 'email' })),
    frontendUrl: t.Optional(t.String({ format: 'uri' })),
  }),
  callback: t.Object({
    code: t.String(),
    state: t.String(),
  }),
  logout: t.Object({
    frontendUrl: t.Optional(t.String({ format: 'uri' })),
  }),
};

export const authRouter: FastifyPluginAsyncTypebox = async (app) => {
  app.post('/authenticate', { schema: { body: tSchemas.authenticate } }, async (req, reply) => {
    const body = req.body;

    const { url } = await oauthProvider.getAuthUrl({
      loginPrompt: body?.loginPrompt,
      email: body?.email,
      frontendUrl: body?.frontendUrl,
    });

    return { url };
  });

  app.post('/callback', { schema: { body: tSchemas.callback } }, async (req, reply) => {
    const { code, state } = req.body;

    const { url, accessToken, refreshToken } = await oauthProvider.getTokenByCode({ code, state });

    reply.setCookie(accessToken.name, accessToken.value, accessToken.options);
    if (refreshToken) reply.setCookie(refreshToken.name, refreshToken.value, refreshToken.options);
    reply.redirect(url);
  });

  app.post('/logout', { schema: { body: tSchemas.logout } }, (req, reply) => {
    const body = req.body;

    const { url, accessToken, refreshToken } = oauthProvider.getLogoutUrl({
      frontendUrl: body?.frontendUrl,
    });

    reply.setCookie(accessToken.name, accessToken.value, accessToken.options);
    reply.setCookie(refreshToken.name, refreshToken.value, refreshToken.options);
    return { url };
  });
};
