import type { FastifyPluginAsyncTypebox } from '@fastify/type-provider-typebox';
import { Type as t } from '@sinclair/typebox';
import axios from 'axios';
import type { FastifyRequest } from 'fastify';
import { OAuthError, type ResultErr } from 'oauth-entra-id';
import { z } from 'zod';
import { serversMap } from '~/env';
import { HttpException } from '~/error/HttpException';
import { mobileOAuthProvider } from '~/oauth';
import { saveMobileTokens, takeMobileTokens } from '~/utils/mobile-tickets';

// Mobile flow of the package: the app gets a ticket with the login URL, opens the URL in the system browser,
// and exchanges the ticket for the tokens when it is back. Tokens travel as Bearer tokens, no cookies are set.
// See "Mobile Authentication Flow" and "Mobile Middleware Flow" in the README.

const tSchemas = {
  login: t.Object({
    loginPrompt: t.Optional(t.Union([t.Literal('email'), t.Literal('select-account'), t.Literal('sso')])),
    email: t.Optional(t.String({ format: 'email' })),
    frontendUrl: t.Optional(t.String({ format: 'uri' })),
    azureId: t.Optional(t.String({ format: 'uuid' })),
  }),
  callback: t.Object({ code: t.String(), state: t.String() }),
  token: t.Object({ ticket: t.String({ minLength: 1 }) }),
  refresh: t.Object({ refreshToken: t.String({ minLength: 1 }) }),
  logout: t.Object({
    frontendUrl: t.Optional(t.String({ format: 'uri' })),
    azureId: t.Optional(t.String({ format: 'uuid' })),
  }),
  onBehalfOf: t.Object({
    services: t.Array(t.String(), { minItems: 1 }),
    azureId: t.Optional(t.String({ format: 'uuid' })),
  }),
  getB2BInfo: t.Object({
    app: t.Union([t.Literal('express'), t.Literal('nestjs'), t.Literal('honojs')]),
    azureId: t.Optional(t.String({ format: 'uuid' })),
  }),
};

const zB2BResponse = z.object({
  pokemon: z.string().trim().min(1).max(32),
  server: z.enum(['express', 'nestjs', 'honojs']),
});

// The package leaves `statusCode` undefined on some errors, which would be answered as 500.
function withStatus(error: ResultErr | OAuthError, fallback: 400 | 401) {
  return new OAuthError({
    message: error.message,
    description: error.description,
    statusCode: error.statusCode ?? fallback,
  });
}

async function orClientError<T>(run: () => Promise<T>): Promise<T> {
  try {
    return await run();
  } catch (error) {
    throw error instanceof OAuthError ? withStatus(error, 400) : error;
  }
}

interface MobileUser {
  azureId: string;
  tenantId: string;
  uniqueId: string;
  roles: string[];
  isApp: false;
  name: string;
  email: string;
}

declare module 'fastify' {
  interface FastifyRequest {
    mobile: { jwt: string; user: MobileUser };
  }
}

async function requireBearer(req: FastifyRequest) {
  const header = req.headers.authorization;
  const token = header?.startsWith('Bearer ') ? header.slice('Bearer '.length) : undefined;

  const at = await mobileOAuthProvider.verifyAccessToken(token);
  if (at.error) throw withStatus(at.error, 401);
  if (at.meta.isApp) throw new HttpException('Forbidden', 403);

  req.mobile = {
    jwt: at.rawJwt,
    user: {
      azureId: at.meta.azureId as string,
      tenantId: at.meta.tenantId as string,
      uniqueId: at.meta.uniqueId as string,
      roles: at.meta.roles as string[],
      isApp: false,
      name: at.meta.name as string,
      email: at.meta.email as string,
    },
  };
}

export const mobileAuthRouter: FastifyPluginAsyncTypebox = async (app) => {
  app.post('/login', { schema: { body: tSchemas.login } }, async (req, reply) => {
    const body = req.body;

    const { authUrl, ticket } = await orClientError(() =>
      mobileOAuthProvider.getAuthUrl({
        loginPrompt: body?.loginPrompt,
        email: body?.email,
        frontendUrl: body?.frontendUrl,
        azureId: body?.azureId,
      }),
    );

    reply.header('Cache-Control', 'no-store');
    return { url: authUrl, ticket };
  });

  // Microsoft posts here (form_post). The tokens wait for the app under the ticket id, the system browser goes back to the app.
  app.post('/callback', { schema: { body: tSchemas.callback } }, async (req, reply) => {
    const { code, state } = req.body;

    const { accessToken, refreshToken, frontendUrl, ticketId } = await orClientError(() =>
      mobileOAuthProvider.getTokenByCode({ code, state }),
    );

    saveMobileTokens(ticketId, { accessToken: accessToken.value, refreshToken: refreshToken.value });
    return reply.redirect(frontendUrl, 303);
  });

  app.post('/token', { schema: { body: tSchemas.token } }, async (req, reply) => {
    const { ticketId, error } = await mobileOAuthProvider.tryDecryptTicket(req.body.ticket);
    if (error) throw withStatus(error, 400);

    const tokens = takeMobileTokens(ticketId);
    if (!tokens) throw new HttpException('Ticket is not ready, expired or already used', 404);

    reply.header('Cache-Control', 'no-store');
    return tokens;
  });

  app.post('/refresh', { schema: { body: tSchemas.refresh } }, async (req, reply) => {
    const rt = await mobileOAuthProvider.tryRefreshTokens(req.body.refreshToken);
    if (rt.error) throw withStatus(rt.error, 401);

    reply.header('Cache-Control', 'no-store');
    return { accessToken: rt.newAccessToken.value, refreshToken: rt.newRefreshToken.value };
  });

  app.post('/logout', { schema: { body: tSchemas.logout } }, async (req, _reply) => {
    const body = req.body;
    const { logoutUrl } = await orClientError(() =>
      mobileOAuthProvider.getLogoutUrl({ frontendUrl: body?.frontendUrl, azureId: body?.azureId }),
    );
    return { url: logoutUrl };
  });
};

export const mobileProtectedRouter: FastifyPluginAsyncTypebox = async (app) => {
  app.addHook('preHandler', requireBearer);

  app.get('/user-info', (req, _reply) => {
    return { user: req.mobile.user };
  });

  // The downstream tokens are returned in the body, the app sends each one as a Bearer token to its service.
  app.post('/on-behalf-of', { schema: { body: tSchemas.onBehalfOf } }, async (req, reply) => {
    const body = req.body;

    const { results } = await orClientError(() =>
      mobileOAuthProvider.getTokenOnBehalfOf({
        accessToken: req.mobile.jwt,
        services: body.services,
        azureId: body.azureId,
      }),
    );

    reply.header('Cache-Control', 'no-store');
    return {
      tokens: results.map(({ serviceName, accessToken }) => ({
        serviceName,
        name: accessToken.name,
        value: accessToken.value,
      })),
    };
  });

  app.post('/get-b2b-info', { schema: { body: tSchemas.getB2BInfo } }, async (req, _reply) => {
    const body = req.body;

    const { result, error } = await mobileOAuthProvider.tryGetB2BToken({ app: body.app, azureId: body.azureId });
    if (error) throw new HttpException('Failed to get B2B token', 500);

    const axiosResponse = await axios.get(`${serversMap[body.app]}/protected/b2b-info`, {
      headers: { Authorization: `Bearer ${result.token}` },
    });
    const { data: b2bRes, error: b2bResError } = zB2BResponse.safeParse(axiosResponse.data);
    if (b2bResError) throw new HttpException('Invalid response from B2B service', 500);
    return b2bRes;
  });
};
