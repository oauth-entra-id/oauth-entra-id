import type jwt from 'jsonwebtoken';
import type { JwksClient } from 'jwks-rsa';
import { $err, $ok, OAuthError, type Result } from './error';
import type { B2BApp, JwtClientConfig, MinimalAzure, tryGetB2BTokenResult } from './types';
import { $getAudAndExp, $verifyJwt } from './utils/crypto/jwt';
import { $coreErrors, $jwtClientHelper, $mapAndFilter, TIME_SKEW } from './utils/helpers';
import { $prettyErr, zMethods } from './utils/zod';

export class JwtClient {
  private readonly azure: MinimalAzure;
  private readonly jwksClient: JwksClient;

  constructor(configuration: JwtClientConfig) {
    const result = $jwtClientHelper(configuration);
    if (result.error) throw new OAuthError(result.error);

    this.azure = result.azure;
    this.jwksClient = result.jwksClient;
  }

  /** Verifies the JWT token and returns its payload. */
  async $verifyJwt(jwtToken: string | undefined): Promise<Result<{ payload: jwt.JwtPayload }>> {
    if (!jwtToken) {
      return $err('nullish_value', { error: 'Unauthorized', description: 'Access token is required', status: 401 });
    }

    const { payload, error: payloadError } = await $verifyJwt({
      jwtToken: jwtToken,
      jwksClient: this.jwksClient,
      azure: this.azure,
    });
    if (payloadError) return $err(payloadError);

    return $ok({ payload, isApp: payload.sub === payload.oid });
  }

  /**
   * Acquire client-credential tokens for one or multiple B2B apps.
   * Caches tokens for better performance.
   *
   * @overload
   * @param params.appName - The name of the B2B app to get the token for.
   * @returns A result containing the B2B app token and metadata.
   * @throws {OAuthError} if something goes wrong.
   *
   * @overload
   * @param params.appsNames - An array of B2B app names to get tokens for.
   * @returns Results containing an array of B2B app tokens and metadata.
   * @throws {OAuthError} if something goes wrong.
   */
  async tryGetB2BToken(params: { app: string }): Promise<Result<{ result: tryGetB2BTokenResult }>>;
  async tryGetB2BToken(params: { apps: string[] }): Promise<Result<{ results: tryGetB2BTokenResult[] }>>;
  async tryGetB2BToken(
    params: { app: string } | { apps: string[] },
  ): Promise<Result<{ result: tryGetB2BTokenResult } | { results: tryGetB2BTokenResult[] }>> {
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
            appName: app.appName,
            clientId: app.aud,
            token: app.token,
            msalResponse: app.msalResponse,
            isCached: true,
            expiresAt: app.exp,
          } satisfies tryGetB2BTokenResult;
        }

        const msalResponse = await this.azure.cca?.acquireTokenByClientCredential({
          scopes: [app.scope],
          skipCache: true,
        });
        if (!msalResponse) return null;

        const { aud, exp, error: audError } = $getAudAndExp(msalResponse.accessToken);
        if (audError) return null;

        this.azure.b2bApps?.set(app.appName, {
          appName: app.appName,
          scope: app.scope,
          token: msalResponse.accessToken,
          exp: exp - TIME_SKEW,
          aud: aud,
          msalResponse: msalResponse,
        } satisfies B2BApp);

        return {
          appName: app.appName,
          clientId: aud,
          token: msalResponse.accessToken,
          msalResponse: msalResponse,
          isCached: false,
          expiresAt: 0,
        } satisfies tryGetB2BTokenResult;
      });

      if (!results || results.length === 0) {
        return $err('internal', { error: 'Failed to get B2B token', status: 500 });
      }

      return $ok('app' in params ? { result: results[0] as tryGetB2BTokenResult } : { results });
    } catch (err) {
      return $coreErrors(err, 'tryGetB2BToken');
    }
  }
}
