import type { JwksClient } from 'jwks-rsa';
import { $err, OAuthError, type Result } from './error';
import type { B2BResult, JwtPayload, LiteConfig, Metadata, MinimalAzure } from './types';
import { $verifyJwt } from './utils/crypto/jwt';
import { $jwtClientHelper, $tryGetB2BToken } from './utils/helpers';
import { zJwt } from './utils/zod';

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
    const result = $jwtClientHelper(configuration);
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
    return await $verifyJwt({ jwtToken: token, jwksClient: this.jwksClient, azure: this.azure });
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
    return await $tryGetB2BToken(params, this.azure.b2bApps, this.azure.cca);
  }
}
