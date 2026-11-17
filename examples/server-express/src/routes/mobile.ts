import axios from 'axios';
import express, { type NextFunction, type Request, type Response, type Router } from 'express';
import { OAuthError, type ResultErr } from 'oauth-entra-id';
import { z } from 'zod';
import { serversMap } from '~/env';
import { HttpException } from '~/error/HttpException';
import { mobileOAuthProvider } from '~/oauth';
import { saveMobileTokens, takeMobileTokens } from '~/utils/mobile-tickets';

// Mobile flow of the package: the app gets a ticket with the login URL, opens the URL in the system browser,
// and exchanges the ticket for the tokens when it is back. Tokens travel as Bearer tokens, no cookies are set.
// See "Mobile Authentication Flow" and "Mobile Middleware Flow" in the README.

const zAvailableServers = z.enum(['nestjs', 'fastify', 'honojs']);

const zSchemas = {
  login: z
    .object({
      loginPrompt: z.enum(['email', 'select-account', 'sso']).optional(),
      email: z.email().optional(),
      frontendUrl: z.url().optional(),
      azureId: z.uuid().optional(),
    })
    .default({}),
  callback: z.object({ code: z.string(), state: z.string() }),
  token: z.object({ ticket: z.string().min(1) }),
  refresh: z.object({ refreshToken: z.string().min(1) }),
  logout: z.object({ frontendUrl: z.url().optional(), azureId: z.uuid().optional() }).default({}),
  onBehalfOf: z.object({ services: z.array(z.string()).min(1), azureId: z.uuid().optional() }),
  getB2BInfo: z.object({ app: zAvailableServers, azureId: z.uuid().optional() }),
};

const zB2BResponse = z.object({
  pokemon: z.string().trim().min(1).max(32),
  server: zAvailableServers,
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

function parse<T extends z.ZodType>(schema: T, body: unknown): z.infer<T> {
  const { data, error } = schema.safeParse(body);
  if (error) throw new HttpException('Invalid params', 400);
  return data;
}

export const mobileAuthRouter: Router = express.Router();

mobileAuthRouter.post('/login', async (req, res) => {
  const body = parse(zSchemas.login, req.body);

  const { authUrl, ticket } = await orClientError(() =>
    mobileOAuthProvider.getAuthUrl({
      loginPrompt: body.loginPrompt,
      email: body.email,
      frontendUrl: body.frontendUrl,
      azureId: body.azureId,
    }),
  );

  res.set('Cache-Control', 'no-store').status(200).json({ url: authUrl, ticket });
});

// Microsoft posts here (form_post). The tokens wait for the app under the ticket id, the system browser goes back to the app.
mobileAuthRouter.post('/callback', async (req, res) => {
  const { code, state } = parse(zSchemas.callback, req.body);

  const { accessToken, refreshToken, frontendUrl, ticketId } = await orClientError(() =>
    mobileOAuthProvider.getTokenByCode({ code, state }),
  );

  saveMobileTokens(ticketId, { accessToken: accessToken.value, refreshToken: refreshToken.value });
  res.redirect(303, frontendUrl);
});

mobileAuthRouter.post('/token', async (req, res) => {
  const { ticket } = parse(zSchemas.token, req.body);

  const { ticketId, error } = await mobileOAuthProvider.tryDecryptTicket(ticket);
  if (error) throw withStatus(error, 400);

  const tokens = takeMobileTokens(ticketId);
  if (!tokens) throw new HttpException('Ticket is not ready, expired or already used', 404);

  res.set('Cache-Control', 'no-store').status(200).json(tokens);
});

mobileAuthRouter.post('/refresh', async (req, res) => {
  const { refreshToken } = parse(zSchemas.refresh, req.body);

  const rt = await mobileOAuthProvider.tryRefreshTokens(refreshToken);
  if (rt.error) throw withStatus(rt.error, 401);

  res
    .set('Cache-Control', 'no-store')
    .status(200)
    .json({ accessToken: rt.newAccessToken.value, refreshToken: rt.newRefreshToken.value });
});

mobileAuthRouter.post('/logout', async (req, res) => {
  const body = parse(zSchemas.logout, req.body);
  const { logoutUrl } = await orClientError(() => mobileOAuthProvider.getLogoutUrl(body));
  res.status(200).json({ url: logoutUrl });
});

async function requireBearer(req: Request, res: Response, next: NextFunction) {
  const header = req.headers.authorization;
  const token = header?.startsWith('Bearer ') ? header.slice('Bearer '.length) : undefined;

  const at = await mobileOAuthProvider.verifyAccessToken(token);
  if (at.error) throw withStatus(at.error, 401);
  if (at.meta.isApp) throw new HttpException('Forbidden', 403);

  res.locals.mobileJwt = at.rawJwt;
  res.locals.mobileUser = {
    azureId: at.meta.azureId,
    tenantId: at.meta.tenantId,
    uniqueId: at.meta.uniqueId,
    roles: at.meta.roles,
    isApp: false,
    name: at.meta.name,
    email: at.meta.email,
  };
  next();
}

export const mobileProtectedRouter: Router = express.Router();

mobileProtectedRouter.use(requireBearer);

mobileProtectedRouter.get('/user-info', (_req, res) => {
  res.status(200).json({ user: res.locals.mobileUser });
});

// The downstream tokens are returned in the body, the app sends each one as a Bearer token to its service.
mobileProtectedRouter.post('/on-behalf-of', async (req, res) => {
  const body = parse(zSchemas.onBehalfOf, req.body);

  const { results } = await orClientError(() =>
    mobileOAuthProvider.getTokenOnBehalfOf({
      accessToken: res.locals.mobileJwt,
      services: body.services,
      azureId: body.azureId,
    }),
  );

  res
    .set('Cache-Control', 'no-store')
    .status(200)
    .json({
      tokens: results.map(({ serviceName, accessToken }) => ({
        serviceName,
        name: accessToken.name,
        value: accessToken.value,
      })),
    });
});

mobileProtectedRouter.post('/get-b2b-info', async (req, res) => {
  const body = parse(zSchemas.getB2BInfo, req.body);

  const { result, error } = await mobileOAuthProvider.tryGetB2BToken({ app: body.app, azureId: body.azureId });
  if (error) throw new HttpException('Failed to get B2B token', 500);

  const axiosResponse = await axios.get(`${serversMap[body.app]}/protected/b2b-info`, {
    headers: { Authorization: `Bearer ${result.token}` },
  });
  const { data: b2bRes, error: b2bResError } = zB2BResponse.safeParse(axiosResponse.data);
  if (b2bResError) throw new HttpException('Invalid B2B response', 500);
  res.status(200).json(b2bRes);
});
