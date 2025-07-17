import type { JwksClient } from 'jwks-rsa';
import { $err, $ok, OAuthError, type Result } from './error';
import type { B2BApp, B2BResult, JwtPayload, LiteConfig, Metadata, MinimalAzure } from './types';
import { $jwtClientConfig } from './utils/config';
import { $getExpiry, $verifyJwt } from './utils/crypto/jwt';
import { $mapAndFilter, TIME_SKEW } from './utils/helpers';
import { $prettyErr, zJwt, zMethods } from './utils/zod';

/**
 * Lightweight provider for verifying JWTs and obtaining B2B app tokens.
 * Does not support PKCE, refresh tokens, encrypted state/cookies, or OBO flow.
 */
export class LiteProvider {
  private readonly azure: MinimalAzure;
  private readonly jwksClient: JwksClient;

  /**
   * @param configuration The OAuth configuration object:
   * - `azure`: clientId, tenantId, and optional clientSecret with B2B apps.
   * @throws {OAuthError} if the config fails validation or has duplicate service names
   */
  constructor(configuration: LiteConfig) {
    const result = $jwtClientConfig(configuration);
    if (result.error) throw new OAuthError(result.error);

    this.azure = result.azure;
    this.jwksClient = result.jwksClient;
  }

  /**
   * Verifies a JWT token and extracts its payload and metadata.
   * @param jwtToken - Microsoft Entra ID Access Token (JWT).
   * @returns A result containing the JWT payload and metadata.
   */
  async $verifyJwt(jwtToken: string | undefined): Promise<Result<{ payload: JwtPayload; meta: Metadata }>> {
    const { data: token, error } = zJwt.safeParse(jwtToken);
    if (error) {
      return $err('jwt_error', { error: 'Unauthorized', description: 'Access token is required', status: 401 });
    }
    return await $verifyJwt({ jwtToken: token, azure: this.azure, jwksClient: this.jwksClient });
  }

  /**
   * Acquire client-credential tokens for one or multiple B2B apps.
   * Caches tokens for better performance.
   *
   * @overload
   * @param params.appName - The name of the B2B app to get the token for.
   * @returns A result containing the B2B app token and metadata.
   *
   * @overload
   * @param params.appsNames - An array of B2B app names to get tokens for.
   * @returns Results containing an array of B2B app tokens and metadata.
   */
  async tryGetB2BToken(params: { app: string }): Promise<Result<{ result: B2BResult }>>;
  async tryGetB2BToken(params: { apps: string[] }): Promise<Result<{ results: B2BResult[] }>>;
  async tryGetB2BToken(
    params: { app: string } | { apps: string[] },
  ): Promise<Result<{ result: B2BResult } | { results: B2BResult[] }>> {
    if (!this.azure.b2bApps || !this.azure.cca) {
      return $err('misconfiguration', { error: 'B2B apps not configured', status: 500 });
    }

    const { data: parsedParams, error: paramsError } = zMethods.tryGetB2BToken.safeParse(params);
    if (paramsError) return $err('bad_request', { error: 'Invalid params', description: $prettyErr(paramsError) });

    const apps = parsedParams.apps.map((app) => this.azure.b2bApps?.get(app)).filter((app) => !!app);
    if (!apps || apps.length === 0) {
      return $err('bad_request', { error: 'Invalid params', description: 'B2B app not found' });
    }

    try {
      const results = await $mapAndFilter(apps, async (app) => {
        if (app.token && app.exp > Date.now() / 1000) {
          return {
            clientId: this.azure.clientId,
            appName: app.appName,
            appId: app.aud,
            token: app.token,
            msalResponse: app.msalResponse,
            isCached: true,
            expiresAt: app.exp,
          } satisfies B2BResult;
        }

        const msalResponse = await this.azure.cca?.acquireTokenByClientCredential({
          scopes: [app.scope],
          skipCache: true,
        });
        if (!msalResponse) return null;

        const { clientId, exp, error: audError } = $getExpiry(msalResponse.accessToken);
        if (audError) return null;

        this.azure.b2bApps?.set(app.appName, {
          appName: app.appName,
          scope: app.scope,
          token: msalResponse.accessToken,
          exp: exp - TIME_SKEW,
          aud: clientId,
          msalResponse: msalResponse,
        } satisfies B2BApp);

        return {
          clientId: this.azure.clientId,
          appName: app.appName,
          appId: clientId,
          token: msalResponse.accessToken,
          msalResponse: msalResponse,
          isCached: false,
          expiresAt: 0,
        } satisfies B2BResult;
      });

      if (!results || results.length === 0) {
        return $err('internal', { error: 'Failed to get B2B token', status: 500 });
      }

      return $ok('app' in params ? { result: results[0] as B2BResult } : { results });
    } catch (err) {
      return $err(
        err instanceof OAuthError
          ? err
          : $err('bad_request', {
              error: 'Failed to get B2B token',
              description: err instanceof Error ? err.message : String(err),
              status: 500,
            }),
      );
    }
  }
}
