import jwt from 'jsonwebtoken';
import type { JwksClient } from 'jwks-rsa';
import { $err, $ok, type Result } from '~/error';
import type { JwtPayload, Metadata } from '~/types';
import { $isString } from '../zod';

export function $extractDataFromPayload(payload: JwtPayload | string): Result<{ meta: Metadata }> {
  if (!payload || typeof payload === 'string') {
    return $err('jwt_error', { error: 'Unauthorized', description: 'Payload is a string or null', status: 401 });
  }

  const isApp = payload.sub === payload.oid;

  return $ok({
    meta: {
      audience: payload.aud as string | undefined,
      issuer: payload.iss,
      subject: payload.sub,
      issuedAt: payload.iat,
      expiration: payload.exp,
      uniqueId: payload.oid as string | undefined,
      appClientId: payload.aud as string | undefined,
      appTenantId: payload.tid as string | undefined,
      roles: payload.roles as string[] | undefined,
      uniqueTokenId: payload.uti as string | undefined,
      ...(isApp
        ? {
            isApp: true as const,
            appId: payload.azp as string | undefined,
          }
        : {
            isApp: false as const,
            name: payload.name as string | undefined,
            email: payload.preferred_username as string | undefined,
          }),
    },
  });
}

export async function $verifyJwt({
  jwksClient,
  azure,
  jwtToken,
}: {
  jwksClient: JwksClient;
  azure: { clientId: string; tenantId: string };
  jwtToken: string;
}): Promise<Result<{ payload: JwtPayload; meta: Metadata }>> {
  const kid = $getKeyId(jwtToken);
  if (kid.error) return $err('jwt_error', { error: 'Unauthorized', description: kid.error.description, status: 401 });

  try {
    const publicKey = await $getPublicKey(jwksClient, kid.result);

    const decodedJwt = jwt.verify(jwtToken, publicKey, {
      algorithms: ['RS256'],
      audience: azure.clientId,
      issuer: `https://login.microsoftonline.com/${azure.tenantId}/v2.0`,
      complete: true,
    });

    const { meta, error } = $extractDataFromPayload(decodedJwt.payload);
    if (error) return $err(error);

    return $ok({ payload: decodedJwt.payload as JwtPayload, meta: meta });
  } catch (err) {
    return $err('jwt_error', {
      error: 'Unauthorized',
      description: `Failed to verify JWT token. Check your Azure Portal, make sure the 'accessTokenAcceptedVersion' is set to '2' in the 'Manifest' area. Error: ${err instanceof Error ? err.message : err}`,
      status: 401,
    });
  }
}

export function $getPublicKey(jwksClient: JwksClient, kid: string): Promise<string> {
  return new Promise((resolve, reject) => {
    jwksClient.getSigningKey(kid, (err, key) => {
      if (err || !key) {
        reject(new Error('Error retrieving signing key'));
        return;
      }
      const publicKey = key.getPublicKey();
      if (!publicKey) {
        reject(new Error('Public key not found'));
        return;
      }
      resolve(publicKey);
    });
  });
}

export function $decodeJwt(jwtToken: string): Result<{ decodedJwt: jwt.Jwt }> {
  if (!$isString(jwtToken)) return $err('nullish_value', { error: 'Invalid JWT token', description: 'Empty JWT' });

  try {
    const decodedJwt = jwt.decode(jwtToken, { complete: true });
    if (!decodedJwt) return $err('jwt_error', { error: 'Invalid JWT token', description: "Couldn't decode JWT token" });

    return $ok({ decodedJwt });
  } catch {
    return $err('jwt_error', { error: 'Invalid JWT token', description: "Couldn't decode JWT token" });
  }
}

export function $getAudienceAndExpiry(jwtToken: string): Result<{ aud: string; exp: number }> {
  const { decodedJwt, error } = $decodeJwt(jwtToken);
  if (error) return $err(error);

  if (typeof decodedJwt.payload === 'string') {
    return $err('jwt_error', { error: 'Invalid JWT token', description: "Couldn't get the JWT payload" });
  }

  const aud = decodedJwt.payload.aud;
  if (typeof aud !== 'string')
    return $err('jwt_error', {
      error: 'Invalid JWT token',
      description: `Invalid audience (aud) claim, payload: ${JSON.stringify(decodedJwt.payload)}`,
    });

  const exp = decodedJwt.payload.exp;
  if (typeof exp !== 'number')
    return $err('jwt_error', {
      error: 'Invalid JWT token',
      description: `Invalid expiration (exp) claim, payload: ${JSON.stringify(decodedJwt.payload)}`,
    });

  return $ok({ aud, exp });
}

export function $getKeyId(jwtToken: string): Result<string> {
  const { decodedJwt, error } = $decodeJwt(jwtToken);
  if (error) return $err(error);

  const kid = decodedJwt.header.kid;
  if (typeof kid !== 'string')
    return $err('jwt_error', {
      error: 'Invalid JWT token',
      description: `Invalid key ID (kid) claim, header: ${JSON.stringify(decodedJwt.header)}`,
    });

  return $ok(kid);
}
