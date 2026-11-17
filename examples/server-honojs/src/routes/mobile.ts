import { zValidator } from '@hono/zod-validator';
import axios from 'axios';
import { Hono } from 'hono';
import { createMiddleware } from 'hono/factory';
import { HTTPException } from 'hono/http-exception';
import { OAuthError, type ResultErr } from 'oauth-entra-id';
import { z } from 'zod';
import { serversMap } from '~/env';
import { mobileOAuthProvider } from '~/oauth';
import { saveMobileTokens, takeMobileTokens } from '~/utils/mobile-tickets';

// Mobile flow of the package: the app gets a ticket with the login URL, opens the URL in the system browser,
// and exchanges the ticket for the tokens when it is back. Tokens travel as Bearer tokens, no cookies are set.
// See "Mobile Authentication Flow" and "Mobile Middleware Flow" in the README.

const zAvailableServers = z.enum(['express', 'nestjs', 'fastify']);

const zSchemas = {
  login: z
    .object({
      loginPrompt: z.enum(['email', 'select-account', 'sso']).optional(),
      email: z.email().optional(),
      frontendUrl: z.url().optional(),
      azureId: z.uuid().optional(),
    })
    .optional(),
  callback: z.object({ code: z.string(), state: z.string() }),
  token: z.object({ ticket: z.string().min(1) }),
  refresh: z.object({ refreshToken: z.string().min(1) }),
  logout: z.object({ frontendUrl: z.url().optional(), azureId: z.uuid().optional() }).optional(),
  onBehalfOf: z.object({ services: z.array(z.string()).min(1), azureId: z.uuid().optional() }),
  getB2BInfo: z.object({ app: zAvailableServers, azureId: z.uuid().optional() }),
};

const zB2BResponse = z.object({
  pokemon: z.string().trim().min(1).max(32),
  server: zAvailableServers,
});

// The package leaves `statusCode` undefined on some errors, which would be answered as 200 or 500.
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

type MobileEnv = { Variables: { mobileJwt: string; mobileUser: MobileUser } };

export const mobileAuthRouter = new Hono<MobileEnv>();

mobileAuthRouter.post('/login', zValidator('json', zSchemas.login), async (c) => {
  const body = c.req.valid('json');

  const { authUrl, ticket } = await orClientError(() =>
    mobileOAuthProvider.getAuthUrl({
      loginPrompt: body?.loginPrompt,
      email: body?.email,
      frontendUrl: body?.frontendUrl,
      azureId: body?.azureId,
    }),
  );

  c.header('Cache-Control', 'no-store');
  return c.json({ url: authUrl, ticket });
});

// Microsoft posts here (form_post). The tokens wait for the app under the ticket id, the system browser goes back to the app.
mobileAuthRouter.post('/callback', zValidator('form', zSchemas.callback), async (c) => {
  const { code, state } = c.req.valid('form');
  const { accessToken, refreshToken, frontendUrl, ticketId } = await orClientError(() =>
    mobileOAuthProvider.getTokenByCode({ code, state }),
  );

  saveMobileTokens(ticketId, { accessToken: accessToken.value, refreshToken: refreshToken.value });
  return c.redirect(frontendUrl, 303);
});

mobileAuthRouter.post('/token', zValidator('json', zSchemas.token), async (c) => {
  const { ticket } = c.req.valid('json');

  const { ticketId, error } = await mobileOAuthProvider.tryDecryptTicket(ticket);
  if (error) throw withStatus(error, 400);

  const tokens = takeMobileTokens(ticketId);
  if (!tokens) throw new HTTPException(404, { message: 'Ticket is not ready, expired or already used' });

  c.header('Cache-Control', 'no-store');
  return c.json(tokens);
});

mobileAuthRouter.post('/refresh', zValidator('json', zSchemas.refresh), async (c) => {
  const { refreshToken } = c.req.valid('json');

  const rt = await mobileOAuthProvider.tryRefreshTokens(refreshToken);
  if (rt.error) throw withStatus(rt.error, 401);

  c.header('Cache-Control', 'no-store');
  return c.json({ accessToken: rt.newAccessToken.value, refreshToken: rt.newRefreshToken.value });
});

mobileAuthRouter.post('/logout', zValidator('json', zSchemas.logout), async (c) => {
  const body = c.req.valid('json');
  const { logoutUrl } = await orClientError(() =>
    mobileOAuthProvider.getLogoutUrl({ frontendUrl: body?.frontendUrl, azureId: body?.azureId }),
  );
  return c.json({ url: logoutUrl });
});

const requireBearer = createMiddleware<MobileEnv>(async (c, next) => {
  const header = c.req.header('Authorization');
  const token = header?.startsWith('Bearer ') ? header.slice('Bearer '.length) : undefined;

  const at = await mobileOAuthProvider.verifyAccessToken(token);
  if (at.error) throw withStatus(at.error, 401);
  if (at.meta.isApp) throw new HTTPException(403, { message: 'Forbidden' });

  c.set('mobileJwt', at.rawJwt);
  c.set('mobileUser', {
    azureId: at.meta.azureId as string,
    tenantId: at.meta.tenantId as string,
    uniqueId: at.meta.uniqueId as string,
    roles: at.meta.roles as string[],
    isApp: false,
    name: at.meta.name as string,
    email: at.meta.email as string,
  });
  await next();
});

export const mobileProtectedRouter = new Hono<MobileEnv>();

mobileProtectedRouter.use(requireBearer);

mobileProtectedRouter.get('/user-info', (c) => {
  return c.json({ user: c.get('mobileUser') });
});

// The downstream tokens are returned in the body, the app sends each one as a Bearer token to its service.
mobileProtectedRouter.post('/on-behalf-of', zValidator('json', zSchemas.onBehalfOf), async (c) => {
  const body = c.req.valid('json');

  const { results } = await orClientError(() =>
    mobileOAuthProvider.getTokenOnBehalfOf({
      accessToken: c.get('mobileJwt'),
      services: body.services,
      azureId: body.azureId,
    }),
  );

  c.header('Cache-Control', 'no-store');
  return c.json({
    tokens: results.map(({ serviceName, accessToken }) => ({
      serviceName,
      name: accessToken.name,
      value: accessToken.value,
    })),
  });
});

mobileProtectedRouter.post('/get-b2b-info', zValidator('json', zSchemas.getB2BInfo), async (c) => {
  const body = c.req.valid('json');

  const { result, error } = await mobileOAuthProvider.tryGetB2BToken({ app: body.app, azureId: body.azureId });
  if (error) throw new HTTPException(500, { message: 'Failed to get B2B token' });

  const axiosResponse = await axios.get(`${serversMap[body.app]}/protected/b2b-info`, {
    headers: { Authorization: `Bearer ${result.token}` },
  });
  const { data: b2bRes, error: b2bResError } = zB2BResponse.safeParse(axiosResponse.data);
  if (b2bResError) throw new HTTPException(500, { message: 'Invalid response from B2B server' });
  return c.json(b2bRes);
});
