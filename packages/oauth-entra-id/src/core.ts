import type { CryptoProvider } from '@azure/msal-node';
import type { WebSecretKey } from 'cipher-kit/web-api';
import type { JwksClient } from 'jwks-rsa';
import type { z } from 'zod';
import { $err, $fmtError, $ok, OAuthError, type Result } from './error';
import type {
  Azure,
  B2BApp,
  B2BResult,
  BaseCookieOptions,
  Cookies,
  CryptoType,
  EncryptionKeys,
  JwtPayload,
  LoginPrompt,
  Metadata,
  MsalResponse,
  NonEmptyArray,
  OAuthConfig,
  OAuthSettings,
  OboResult,
} from './types';
import { $oauthConfig } from './utils/config';
import { $getCookieNames, $getCookieOptions } from './utils/cookie-options';
import { $generateUuid } from './utils/encrypt';
import {
  $decryptAccessToken,
  $decryptRefreshToken,
  $decryptState,
  $decryptTicket,
  $encryptAccessToken,
  $encryptRefreshToken,
  $encryptState,
  $encryptTicket,
} from './utils/encrypt-tokens';
import { $mapAndFilter, $transformToMsalPrompt, TIME_SKEW } from './utils/helpers';
import { $getExpiry, $verifyJwt } from './utils/jwt';
import { zInjectedData, zMethods, type zState } from './utils/zod';

/**
 * Core OAuth2/PKCE provider for Microsoft Entra ID (Azure AD).
 *
 * Responsibilities:
 *  - PKCE authorization URL generation
 *  - Authorization‐code and refresh‐token exchanges
 *  - Secure encryption/decryption of state & cookies
 *  - JWT validation via JWKS
 *  - B2B client‐credentials flow
 *  - On‐Behalf-Of (OBO) flow for downstream services
 *
 * Designed to be framework-agnostic (Express, NestJS, etc.)
 */
export class OAuthProvider {
  private readonly azures: NonEmptyArray<Azure>;
  private readonly frontendUrls: NonEmptyArray<string>;
  private readonly frontendWhitelist: Set<string>;
  private readonly serverCallbackUrl: string;
  private readonly baseCookieOptions: BaseCookieOptions;
  private readonly encryptionKeys: EncryptionKeys;
  private readonly msalCryptoProvider: CryptoProvider;
  private readonly jwksClient: JwksClient;
  readonly settings: OAuthSettings;

  /**
   * @param configuration The OAuth configuration object:
   * - `azure`: clientId, tenantId, scopes, clientSecret, B2B apps, and downstream services. Can be an array of Azure configurations.
   * - `frontendUrl`: allowed redirect URIs
   * - `serverCallbackUrl`: your server’s Azure callback endpoint
   * - `encryptionKey`: 32 characters base encryption secret
   * - `advanced`: optional behaviors
   * @throws {OAuthError} if the config fails validation or has duplicate service names
   */
  constructor(configuration: OAuthConfig) {
    const result = $oauthConfig(configuration);
    if (result.error) throw new OAuthError(result.error);

    this.azures = result.azures;
    this.frontendUrls = result.frontendUrls;
    this.frontendWhitelist = result.frontendWhitelist;
    this.serverCallbackUrl = result.serverCallbackUrl;
    this.baseCookieOptions = result.baseCookieOptions;
    this.encryptionKeys = result.encryptionKeys;
    this.msalCryptoProvider = result.msalCryptoProvider;
    this.jwksClient = result.jwksClient;
    this.settings = result.settings;
  }

  /**
   * Generate an OAuth2 authorization URL for user login (PKCE-backed).
   *
   * @param params (optional) - Parameters to customize the auth URL:
   * - `loginPrompt` (optional) - Override the default prompt (`sso`|`email`|`select-account`)
   * - `email` (optional) - Email address to pre-fill the login form
   * - `frontendUrl` (optional) - Frontend URL override to redirect the user after authentication
   * - `azureId` (optional) - Azure configuration ID to use, relevant if multiple Azure configurations (Defaults to the first one)
   * @returns A result containing the authorization URL and a ticket (which is used for bearer flow only)
   * @throws {OAuthError} if something goes wrong.
   */
  async getAuthUrl(params?: {
    loginPrompt?: LoginPrompt;
    email?: string;
    frontendUrl?: string;
    azureId?: string;
  }): Promise<{
    authUrl: string;
    ticket: string;
  }> {
    const { data: parsedParams, error: paramsError } = zMethods.getAuthUrl.safeParse(params);
    if (paramsError) throw new OAuthError({ msg: 'Invalid Params', desc: $fmtError(paramsError) });

    const { azure, error: azureError } = this.$getAzure({
      azureId: parsedParams.azureId,
      fallbackToDefault: true,
      status: 400,
    });
    if (azureError) throw new OAuthError(azureError);

    if (parsedParams.loginPrompt === 'email' && !parsedParams.email) {
      throw new OAuthError({ msg: 'Invalid params', desc: 'Email is required when loginPrompt is set to "email"' });
    }

    if (parsedParams.frontendUrl && !this.frontendWhitelist.has(new URL(parsedParams.frontendUrl).host)) {
      throw new OAuthError({ msg: 'Forbidden', desc: 'Unlisted host frontend URL', status: 403 });
    }

    const { uuid: ticketId, error: uuidError } = $generateUuid(this.settings.cryptoType);
    if (uuidError) throw new OAuthError(uuidError);

    try {
      const [pkce, { encrypted, error: ticketError }] = await Promise.all([
        this.msalCryptoProvider.generatePkceCodes(),
        this.$encryptToken('ticket', ticketId),
      ]);
      if (ticketError) throw new OAuthError(ticketError);

      const prompt = $transformToMsalPrompt(parsedParams.loginPrompt ?? this.settings.loginPrompt, parsedParams.email);
      const params = { nonce: this.msalCryptoProvider.createNewGuid(), loginHint: parsedParams.email, prompt };

      const { encrypted: encryptedState, error: encryptError } = await this.$encryptToken('state', {
        azureId: azure.clientId,
        frontendUrl: parsedParams.frontendUrl ?? this.frontendUrls[0],
        codeVerifier: pkce.verifier,
        ticketId: ticketId,
        ...params,
      } satisfies z.infer<typeof zState>);
      if (encryptError) throw new OAuthError(encryptError);

      const authUrl = await azure.cca.getAuthCodeUrl({
        nonce: params.nonce,
        loginHint: params.loginHint,
        prompt: params.prompt,
        state: encryptedState,
        scopes: azure.scopes,
        redirectUri: this.serverCallbackUrl,
        responseMode: 'form_post',
        codeChallengeMethod: 'S256',
        codeChallenge: pkce.challenge,
      });

      if (new URL(authUrl).hostname !== 'login.microsoftonline.com') {
        throw new OAuthError({
          msg: 'Invalid auth URL',
          desc: 'The generated auth URL does not point to Microsoft Entra ID',
          status: 500,
        });
      }
      return { authUrl, ticket: encrypted };
    } catch (error) {
      if (error instanceof OAuthError) throw error;
      throw new OAuthError({
        msg: 'Failed to generate auth URL',
        desc: `Auth URL Generation - ${$fmtError(error)}`,
      });
    }
  }

  /**
   * Exchange an authorization code for encrypted tokens and metadata.
   *
   * @param params - The parameters containing the authorization code and state.
   * - `code` - The authorization code received from the OAuth flow.
   * - `state` -  The state parameter received from Microsoft.
   * @returns A result containing the access token, refresh token (if available), frontend URL, and MSAL response.
   * @throws {OAuthError} if something goes wrong.
   */
  async getTokenByCode(params: { code: string; state: string }): Promise<{
    accessToken: Cookies['AccessToken'];
    refreshToken: Cookies['RefreshToken'];
    frontendUrl: string;
    ticketId: string;
    msalResponse: MsalResponse;
  }> {
    const { data: parsedParams, error: paramsError } = zMethods.getTokenByCode.safeParse(params);
    if (paramsError) throw new OAuthError({ msg: 'Invalid Params', desc: $fmtError(paramsError) });

    const { decrypted: state, error: decryptError } = await this.$decryptToken('state', parsedParams.state);
    if (decryptError) throw new OAuthError(decryptError);

    const { azure, error: azureError } = this.$getAzure({ azureId: state.azureId, status: 400 });
    if (azureError) throw new OAuthError(azureError);

    if (!this.frontendWhitelist.has(new URL(state.frontendUrl).host)) {
      throw new OAuthError({ msg: 'Forbidden', desc: 'Unlisted host frontend URL', status: 403 });
    }

    try {
      const msalResponse = await azure.cca.acquireTokenByCode({
        code: parsedParams.code,
        scopes: azure.scopes,
        redirectUri: this.serverCallbackUrl,
        codeVerifier: state.codeVerifier,
      });

      const { encryptedAccessToken, encryptedRefreshToken, error } = await this.$extractTokens(azure, msalResponse);
      if (error) throw new OAuthError(error);

      return {
        accessToken: {
          name: azure.cookiesNames.accessTokenName,
          value: encryptedAccessToken,
          options: this.baseCookieOptions.accessTokenOptions,
        },
        refreshToken: {
          name: azure.cookiesNames.refreshTokenName,
          value: encryptedRefreshToken ?? '',
          options: encryptedRefreshToken
            ? this.baseCookieOptions.refreshTokenOptions
            : this.baseCookieOptions.deleteTokenOptions,
        },
        frontendUrl: state.frontendUrl,
        ticketId: state.ticketId,
        msalResponse,
      };
    } catch (err) {
      if (err instanceof OAuthError) throw err;
      throw new OAuthError({
        msg: 'Failed to get token by code',
        desc: `Token Exchange - ${$fmtError(err)} ,Make sure to check Azure credentials (client ID, tenant ID, client secret) and scopes.`,
      });
    }
  }

  /**
   * Build a logout URL and cookie-deletion instructions.
   *
   * @param params (optional) - Parameters to customize the logout URL:
   * - `frontendUrl` (optional) - Frontend URL override to redirect the user after log out
   * - `azureId` (optional) - Azure configuration ID to use, relevant if multiple Azure configurations (Defaults to the first one)
   * @returns A result containing the logout URL and cookie deletion instructions.
   * @throws {OAuthError} if something goes wrong.
   */
  async getLogoutUrl(params?: { frontendUrl?: string; azureId?: string }): Promise<{
    logoutUrl: string;
    deleteAccessToken: Cookies['DeleteAccessToken'];
    deleteRefreshToken: Cookies['DeleteRefreshToken'];
  }> {
    const { data: parsedParams, error: paramsError } = zMethods.getLogoutUrl.safeParse(params);
    if (paramsError) throw new OAuthError({ msg: 'Invalid Params', desc: $fmtError(paramsError) });

    const { azure, error: azureError } = this.$getAzure({
      azureId: parsedParams.azureId,
      fallbackToDefault: true,
      status: 400,
    });
    if (azureError) throw new OAuthError(azureError);

    if (parsedParams.frontendUrl && !this.frontendWhitelist.has(new URL(parsedParams.frontendUrl).host)) {
      throw new OAuthError({ msg: 'Forbidden', desc: 'Unlisted host frontend URL', status: 403 });
    }

    const logoutUrl = new URL(`https://login.microsoftonline.com/${azure.tenantId}/oauth2/v2.0/logout`);
    logoutUrl.searchParams.set('post_logout_redirect_uri', parsedParams.frontendUrl ?? this.frontendUrls[0]);

    return {
      logoutUrl: logoutUrl.toString(),
      deleteAccessToken: {
        name: azure.cookiesNames.accessTokenName,
        value: '',
        options: this.baseCookieOptions.deleteTokenOptions,
      },
      deleteRefreshToken: {
        name: azure.cookiesNames.refreshTokenName,
        value: '',
        options: this.baseCookieOptions.deleteTokenOptions,
      },
    };
  }

  /**
   * Verify the access token (either encrypted or in JWT format) and extract its payload.
   * Make sure that user access tokens are encrypted and app tokens aren't
   *
   * @param accessToken - The access token string either encrypted or in JWT format
   * @returns A result containing the raw access token, its payload, any injected data, and whether it is an app token.
   * @template T - Type of any injected data in the encrypted token
   */
  async verifyAccessToken<T extends object = Record<string, any>>(
    accessToken: string | undefined,
  ): Promise<
    Result<{
      payload: JwtPayload;
      meta: Metadata;
      rawJwt: string;
      injectedData: T | undefined;
      hasInjectedData: boolean;
    }>
  > {
    const { decrypted, azureId, injectedData, wasEncrypted, error } = await this.$decryptToken<T>(
      'accessToken',
      accessToken,
    );
    if (error) return $err({ msg: 'Unauthorized', desc: `Token Decryption - ${$fmtError(error)}`, status: 401 });

    const { azure, error: azureError } = this.$getAzure({ azureId });
    if (azureError) return $err(azureError);

    const at = await $verifyJwt({ jwtToken: decrypted, azure: azure, jwksClient: this.jwksClient });
    if (at.error) return $err(at.error);

    if (this.settings.acceptB2BRequests === false && at.meta.isApp === true) {
      return $err({
        msg: 'B2B requests not allowed',
        desc: 'B2B requests are not allowed, please enable them in the configuration',
        status: 403,
      });
    }

    if (at.meta.isApp === wasEncrypted) {
      return $err({
        msg: 'Unauthorized',
        desc: 'User tokens must be encrypted, app tokens must not be encrypted',
        status: 401,
      });
    }

    return $ok({
      rawJwt: decrypted,
      payload: at.payload,
      meta: at.meta,
      injectedData: injectedData,
      hasInjectedData: !!injectedData,
    });
  }

  /**
   * Verifies and uses the refresh token to get new set of access and refresh tokens.
   *
   * @param refreshToken - Encrypted refresh-token value
   * @returns A result containing the new access token, optional new refresh token, the raw access token, its payload, and the MSAL response.
   */
  async tryRefreshTokens(refreshToken: string | undefined): Promise<
    Result<{
      newAccessToken: Cookies['AccessToken'];
      newRefreshToken: Cookies['RefreshToken'];
      payload: JwtPayload;
      meta: Metadata;
      rawJwt: string;
      msalResponse: MsalResponse;
    }>
  > {
    if (!refreshToken) {
      return $err({ msg: 'Unauthorized', desc: 'Refresh token is required', status: 401 });
    }

    const {
      decrypted: rawRefreshToken,
      azureId,
      error: decryptError,
    } = await this.$decryptToken('refreshToken', refreshToken);
    if (decryptError) {
      return $err({
        msg: 'Unauthorized',
        desc: `Refresh Token Decryption - ${$fmtError(decryptError)}`,
        status: 401,
      });
    }

    const { azure, error: azureError } = this.$getAzure({ azureId });
    if (azureError) return $err(azureError);

    try {
      const msalResponse = await azure.cca.acquireTokenByRefreshToken({
        refreshToken: rawRefreshToken,
        scopes: azure.scopes,
        forceCache: true,
      });
      if (!msalResponse) {
        return $err({ msg: 'Unauthorized', desc: 'Failed to refresh token, no msal response', status: 401 });
      }

      const at = await $verifyJwt({
        jwtToken: msalResponse.accessToken,
        jwksClient: this.jwksClient,
        azure: azure,
      });
      if (at.error) {
        return $err({
          msg: 'Unauthorized',
          desc: `Access Token Verification - ${$fmtError(at.error)}`,
          status: 401,
        });
      }

      const { encryptedAccessToken, encryptedRefreshToken, error } = await this.$extractTokens(azure, msalResponse);
      if (error) return $err({ msg: 'Unauthorized', desc: `Extract Tokens - ${$fmtError(error)}`, status: 401 });

      return $ok({
        rawJwt: msalResponse.accessToken,
        payload: at.payload,
        meta: at.meta,
        newAccessToken: {
          name: azure.cookiesNames.accessTokenName,
          value: encryptedAccessToken,
          options: this.baseCookieOptions.accessTokenOptions,
        },
        newRefreshToken: {
          name: azure.cookiesNames.refreshTokenName,
          value: encryptedRefreshToken ?? '',
          options: encryptedRefreshToken
            ? this.baseCookieOptions.refreshTokenOptions
            : this.baseCookieOptions.deleteTokenOptions,
        },
        msalResponse: msalResponse,
      });
    } catch (err) {
      if (err instanceof OAuthError) return $err(err);
      return $err({ msg: 'Unauthorized', desc: `Token Refresh - ${$fmtError(err)}`, status: 401 });
    }
  }

  /**
   * Inject non-sensitive metadata into the access token.
   *
   * @param params - The parameters containing the access token and data to inject.
   * - `accessToken` - The encrypted access token to inject data into.
   * - `data` - The data to inject into the access token.
   * @returns A result containing the new encrypted access token with injected data and the injected data.
   * @template T - Type of the data to inject into the access token.
   */
  async tryInjectData<T extends object = Record<string, any>>(params: {
    accessToken: string;
    data: T;
  }): Promise<Result<{ newAccessToken: Cookies['AccessToken']; injectedData: T }>> {
    const { decrypted: rawAccessToken, azureId, error } = await this.$decryptToken('accessToken', params.accessToken);
    if (error) return $err(error);

    const { azure, error: azureError } = this.$getAzure({ azureId });
    if (azureError) return $err(azureError);

    const { data: dataToInject, error: dataToInjectError } = zInjectedData.safeParse(params.data);
    if (dataToInjectError) return $err({ msg: 'Invalid Params', desc: $fmtError(dataToInjectError) });

    const { encrypted, error: encryptError } = await this.$encryptToken('accessToken', rawAccessToken, {
      azureId,
      expiry: this.settings.cookies.accessTokenExpiry,
      dataToInject: dataToInject,
    });
    if (encryptError) return $err(encryptError);

    return $ok({
      newAccessToken: {
        name: azure.cookiesNames.accessTokenName,
        value: encrypted,
        options: this.baseCookieOptions.accessTokenOptions,
      },
      injectedData: dataToInject as T,
    });
  }

  /**
   * Decrypts a ticket and returns the ticket ID.
   * Useful for bearer flow.
   *
   * @param ticket - The encrypted ticket string to decrypt (generated by getAuthUrl).
   * @returns A result containing the ticket ID (returned by getTokenByCode).
   */
  async tryDecryptTicket(ticket: string): Promise<Result<{ ticketId: string }>> {
    const { decrypted, error } = await this.$decryptToken('ticket', ticket);
    if (error) return $err(error);
    return $ok({ ticketId: decrypted });
  }

  /**
   * Acquire client-credential tokens for one or multiple B2B apps.
   * Caches tokens for better performance.
   *
   * @overload
   * @param params.appName - The name of the B2B app to get the token for.
   * @param params.azureId (optional) - Azure configuration ID to use, relevant if multiple Azure configurations (Defaults to the first one)
   * @returns A result containing the B2B app token and metadata.
   *
   * @overload
   * @param params.appsNames - An array of B2B app names to get tokens for.
   * @param params.azureId (optional) - Azure configuration ID to use, relevant if multiple Azure configurations (Defaults to the first one)
   * @returns Results containing an array of B2B app tokens and metadata.
   */
  async tryGetB2BToken(params: { app: string; azureId?: string }): Promise<Result<{ result: B2BResult }>>;
  async tryGetB2BToken(params: {
    apps: string[];
    azureId?: string;
  }): Promise<Result<{ results: NonEmptyArray<B2BResult> }>>;
  async tryGetB2BToken(
    params: { azureId?: string } & ({ app: string } | { apps: string[] }),
  ): Promise<Result<{ result: B2BResult } | { results: NonEmptyArray<B2BResult> }>> {
    const { data: parsedParams, error: paramsError } = zMethods.tryGetB2BToken.safeParse(params);
    if (paramsError) return $err({ msg: 'Invalid Params', desc: $fmtError(paramsError) });

    const { azure, error: azureError } = this.$getAzure({
      azureId: parsedParams.azureId,
      fallbackToDefault: true,
      status: 400,
    });
    if (azureError) throw new OAuthError(azureError);
    if (!azure.b2b) return $err({ msg: 'Misconfiguration', desc: 'B2B apps not configured', status: 500 });

    const apps = parsedParams.apps.map((app) => azure.b2b?.get(app)).filter((app) => !!app);
    if (!apps || apps.length === 0) {
      return $err({ msg: 'Invalid Params', desc: 'B2B app not found', status: 400 });
    }

    try {
      const results = (await $mapAndFilter(apps, async (app) => {
        if (app.token && app.exp > Date.now() / 1000) {
          return {
            clientId: azure.clientId,
            appName: app.appName,
            appId: app.aud,
            token: app.token,
            msalResponse: app.msalResponse,
            isCached: true,
            expiresAt: app.exp,
          } satisfies B2BResult;
        }

        const msalResponse = await azure.cca.acquireTokenByClientCredential({ scopes: [app.scope], skipCache: true });
        if (!msalResponse) return null;

        const { clientId, exp, error: audError } = $getExpiry(msalResponse.accessToken);
        if (audError) return null;

        azure.b2b?.set(app.appName, {
          appName: app.appName,
          scope: app.scope,
          token: msalResponse.accessToken,
          exp: exp - TIME_SKEW,
          aud: clientId,
          msalResponse: msalResponse,
        } satisfies B2BApp);

        return {
          clientId: azure.clientId,
          appName: app.appName,
          appId: clientId,
          token: msalResponse.accessToken,
          msalResponse: msalResponse,
          isCached: false,
          expiresAt: 0,
        } satisfies B2BResult;
      })) as NonEmptyArray<B2BResult>;

      if (!results || results.length === 0) {
        return $err({ msg: 'Internal Server Error', desc: 'Failed to get B2B token', status: 500 });
      }

      return $ok('app' in params ? { result: results[0] } : { results });
    } catch (err) {
      if (err instanceof OAuthError) return $err(err);
      return $err({ msg: 'Internal Server Error', desc: $fmtError(err), status: 500 });
    }
  }

  /**
   * Acquire On-Behalf-Of tokens for downstream services.
   *
   * @overload
   * @param params.accessToken - The encrypted access token to use for OBO.
   * @param params.serviceName - The name of the service to get the token for.
   * @param params.azureId (optional) - Azure configuration ID to use, relevant if multiple Azure configurations (Defaults to the first one)
   * @returns A result containing the OBO token and metadata for the specified service.
   * @throws {OAuthError} if something goes wrong.
   *
   * @overload
   * @param params.accessToken - The encrypted access token to use for OBO.
   * @param params.serviceNames - An array of service names to get tokens for.
   * @param params.azureId (optional) - Azure configuration ID to use, relevant if multiple Azure configurations (Defaults to the first one)
   * @returns Results containing an array of OBO tokens and metadata for the specified services.
   * @throws {OAuthError} if something goes wrong.
   */
  async getTokenOnBehalfOf(params: { accessToken: string; service: string; azureId?: string }): Promise<{
    result: OboResult;
  }>;
  async getTokenOnBehalfOf(params: { accessToken: string; services: string[]; azureId?: string }): Promise<{
    results: NonEmptyArray<OboResult>;
  }>;
  async getTokenOnBehalfOf(
    params: ({ service: string } | { services: string[] }) & {
      accessToken: string;
      azureId?: string;
    },
  ): Promise<{ result: OboResult } | { results: NonEmptyArray<OboResult> }> {
    const { data: parsedParams, error: paramsError } = zMethods.getTokenOnBehalfOf.safeParse(params);
    if (paramsError) throw new OAuthError({ msg: 'Invalid Params', desc: $fmtError(paramsError) });

    const { azure, error: azureError } = this.$getAzure({
      azureId: parsedParams.azureId,
      fallbackToDefault: true,
      status: 400,
    });

    if (azureError) throw new OAuthError(azureError);
    if (!azure.obo) throw new OAuthError({ msg: 'Misconfiguration', desc: 'OBO services not configured', status: 500 });

    const services = parsedParams.services.map((service) => azure.obo?.get(service)).filter((service) => !!service);

    if (!services || services.length === 0) {
      throw new OAuthError({ msg: 'Invalid Params', desc: 'OBO service not found', status: 400 });
    }

    const { decrypted: rawAccessToken, error } = await this.$decryptToken('accessToken', parsedParams.accessToken);
    if (error) throw new OAuthError(error);

    try {
      const results = (await $mapAndFilter(services, async (service) => {
        const msalResponse = await azure.cca.acquireTokenOnBehalfOf({
          oboAssertion: rawAccessToken,
          scopes: [service.scope],
          skipCache: true,
        });

        if (!msalResponse) return null;

        const { clientId, error: audError } = $getExpiry(msalResponse.accessToken);

        if (audError) return null;

        const { encrypted, error } = await this.$encryptToken('accessToken', msalResponse.accessToken, {
          azureId: clientId,
          expiry: service.atExp,
          cryptoType: service.cryptoType,
          otherSecretKey: `access-token-${service.encryptionKey}`,
        });

        if (error) return null;

        const cookieOptions = $getCookieOptions({
          secure: service.isSecure,
          sameSite: service.isSamesite,
          timeUnit: this.settings.cookies.timeUnit,
          atExp: service.atExp,
          rtExp: 0, // No refresh token
        });

        const { accessTokenName } = $getCookieNames(clientId, service.isSecure);

        return {
          clientId: azure.clientId,
          serviceName: service.serviceName,
          serviceId: clientId,
          accessToken: { name: accessTokenName, value: encrypted, options: cookieOptions.accessTokenOptions },
          msalResponse: msalResponse,
        } satisfies OboResult;
      })) as NonEmptyArray<OboResult>;

      if (!results || results.length === 0) {
        throw new OAuthError({ msg: 'Internal Server Error', desc: 'Failed to get OBO token', status: 500 });
      }

      return 'service' in params ? { result: results[0] } : { results };
    } catch (error) {
      if (error instanceof OAuthError) throw error;
      throw new OAuthError({ msg: 'Internal Server Error', desc: $fmtError(error), status: 500 });
    }
  }

  private $getAzure({
    azureId,
    fallbackToDefault = false,
    status = 401,
  }: {
    azureId: string | undefined;
    fallbackToDefault?: boolean;
    status?: 401 | 400;
  }): Result<{ azure: Azure }> {
    const azure = azureId ? this.azures.find((azure) => azure.clientId === azureId) : undefined;
    if (azure) return $ok({ azure });

    if (fallbackToDefault) return $ok({ azure: this.azures[0] });

    return $err({
      msg: status === 401 ? 'Unauthorized' : 'Invalid Params',
      desc: 'Azure configuration not found for the given client ID',
      status,
    });
  }

  /** Extracts and encrypts both tokens */
  private async $extractTokens(
    azure: Azure,
    msalResponse: MsalResponse,
  ): Promise<Result<{ encryptedAccessToken: string; encryptedRefreshToken: string | null }>> {
    const [accessTokenRes, refreshTokenRes] = await Promise.all([
      this.$encryptToken('accessToken', msalResponse.accessToken, {
        azureId: azure.clientId,
        expiry: this.settings.cookies.accessTokenExpiry,
      }),
      this.$obtainRefreshToken(azure, msalResponse),
    ]);

    if (accessTokenRes.error) return $err(accessTokenRes.error);
    // ! If the refresh token has any error, we still return the access token

    return $ok({
      encryptedAccessToken: accessTokenRes.encrypted,
      encryptedRefreshToken: refreshTokenRes.encrypted ?? null,
    });
  }

  /** Extracts the refresh token from the cache that msal created, and removes the account from the cache. */
  private async $obtainRefreshToken(azure: Azure, msalResponse: MsalResponse): Promise<Result<{ encrypted: string }>> {
    try {
      const cache = azure.cca.getTokenCache();
      const serializedCache = JSON.parse(cache.serialize());
      const refreshTokens = serializedCache?.RefreshToken ?? {};
      const keys = typeof refreshTokens === 'object' ? Object.keys(refreshTokens) : [];
      const refreshTokenKey = keys.find((key) => key.startsWith(msalResponse.uniqueId));
      if (msalResponse.account) await cache.removeAccount(msalResponse.account);
      const refreshToken = refreshTokenKey ? (refreshTokens[refreshTokenKey].secret as string) : undefined;
      return await this.$encryptToken('refreshToken', refreshToken, {
        azureId: azure.clientId,
        expiry: this.settings.cookies.refreshTokenExpiry,
      });
    } catch {
      return $err({
        msg: 'Failed to obtain refresh token',
        desc: 'Failed to obtain refresh token from MSAL cache',
        status: 500,
      });
    }
  }

  /** Updates the secret key for a specific token type if it is a string. */
  private $updateSecretKey(keyType: keyof typeof this.encryptionKeys, secretKey: WebSecretKey | undefined) {
    if (this.settings.cryptoType !== 'web-api' || !secretKey) return;
    const currentKey = this.encryptionKeys[keyType];
    if (typeof currentKey === 'string') {
      this.encryptionKeys[keyType] = secretKey;
    }
  }

  private async $encryptToken<T extends object = Record<string, any>>(
    keyType: 'accessToken',
    value: string | undefined,
    params?: { expiry: number; azureId: string; dataToInject?: T; otherSecretKey?: string; cryptoType?: CryptoType },
  ): Promise<Result<{ encrypted: string }>>;
  private async $encryptToken(
    keyType: 'refreshToken',
    value: string | undefined,
    params?: { expiry: number; azureId: string },
  ): Promise<Result<{ encrypted: string }>>;
  private async $encryptToken(keyType: 'ticket', value: string | undefined): Promise<Result<{ encrypted: string }>>;
  private async $encryptToken(keyType: 'state', value: object | undefined): Promise<Result<{ encrypted: string }>>;
  private async $encryptToken<T extends object = Record<string, any>>(
    keyType: keyof typeof this.encryptionKeys,
    value: string | object | undefined,
    params?: { expiry?: number; azureId?: string; dataToInject?: T; otherSecretKey?: string; cryptoType?: CryptoType },
  ): Promise<Result<{ encrypted: string }>> {
    const baseParams = {
      key: params?.otherSecretKey ?? this.encryptionKeys[keyType],
      cryptoType: params?.cryptoType ?? this.settings.cryptoType,
      $updateSecretKey: this.$updateSecretKey.bind(this),
    };
    switch (keyType) {
      case 'accessToken':
        return $encryptAccessToken<T>(value as string | null, {
          ...baseParams,
          expiry: params?.expiry as number,
          azureId: params?.azureId as string,
          isOtherKey: !!params?.otherSecretKey,
          dataToInject: params?.dataToInject,
          disableCompression: this.settings.disableCompression,
        });
      case 'refreshToken':
        return $encryptRefreshToken(value as string | null, {
          ...baseParams,
          expiry: params?.expiry as number,
          azureId: params?.azureId as string,
        });
      case 'state':
        return $encryptState(value as object | null, baseParams);
      case 'ticket':
        return $encryptTicket(value as string | null, baseParams);
      default:
        return $err({
          msg: 'Invalid encryption key type',
          desc: `Key type '${keyType}' is not supported for encryption`,
        });
    }
  }

  private async $decryptToken<T extends object = Record<string, any>>(
    keyType: 'accessToken',
    value: string | undefined,
  ): Promise<Result<{ decrypted: string; azureId: string; injectedData?: T; wasEncrypted: boolean }>>;
  private async $decryptToken(
    keyType: 'refreshToken',
    value: string | undefined,
  ): Promise<Result<{ decrypted: string; azureId: string }>>;
  private async $decryptToken(
    keyType: 'state',
    value: string | undefined,
  ): Promise<Result<{ decrypted: z.infer<typeof zState> }>>;
  private async $decryptToken(keyType: 'ticket', value: string | undefined): Promise<Result<{ decrypted: string }>>;
  private async $decryptToken<T extends object = Record<string, any>>(
    keyType: keyof typeof this.encryptionKeys,
    value: string | undefined,
  ): Promise<
    Result<{ decrypted: string | z.infer<typeof zState>; injectedData?: T; wasEncrypted?: boolean; azureId?: string }>
  > {
    const baseParams = {
      key: this.encryptionKeys[keyType],
      cryptoType: this.settings.cryptoType,
      $updateSecretKey: this.$updateSecretKey.bind(this),
    };
    switch (keyType) {
      case 'accessToken':
        return $decryptAccessToken(value, baseParams);
      case 'refreshToken':
        return $decryptRefreshToken(value, baseParams);
      case 'state':
        return $decryptState(value, baseParams);
      case 'ticket':
        return $decryptTicket(value, baseParams);
      default:
        return $err({
          msg: 'Invalid encryption key type',
          desc: `Key type '${keyType}' is not supported for encryption`,
        });
    }
  }
}
