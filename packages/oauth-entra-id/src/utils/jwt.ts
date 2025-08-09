import jwt from 'jsonwebtoken';
import type { JwksClient } from 'jwks-rsa';
import { $err, $ok, type Result } from '~/error';
import type { JwtPayload, Metadata } from '~/types';
import { $isStr } from './zod';

export function $extractDataFromPayload(payload: JwtPayload | string): Result<{ meta: Metadata }> {
  if (!payload || typeof payload === 'string') {
    return $err({ msg: 'Unauthorized', desc: 'Payload is a string or null', status: 401 });
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
      azureId: payload.aud as string | undefined,
      tenantId: payload.tid as string | undefined,
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
  jwtToken,
  azure,
  jwksClient,
}: {
  jwtToken: string;
  azure: { clientId: string; tenantId: string };
  jwksClient: JwksClient;
}): Promise<Result<{ payload: JwtPayload; meta: Metadata }>> {
  const { kid, tenantId, error } = $getKeyId(jwtToken);
  if (error)
    return $err({
      msg: 'Unauthorized',
      desc: `Key ID extraction error: message: ${error.message}, description: ${error.description}`,
      status: 401,
    });

  if (azure.tenantId !== 'common' && tenantId !== azure.tenantId) {
    return $err({
      msg: 'Unauthorized',
      desc: `Invalid tenant ID (tid) claim, expected: ${azure.tenantId}, got: ${tenantId}`,
      status: 401,
    });
  }

  try {
    const publicKey = await $getPublicKey(jwksClient, kid);

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
    return $err({
      msg: 'Unauthorized',
      desc: `Failed to verify JWT token. Check your Azure Portal, make sure the 'accessTokenAcceptedVersion' is set to '2' in the 'Manifest' area. Error: ${err instanceof Error ? err.message : err}`,
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
  if (!$isStr(jwtToken)) return $err({ msg: 'Invalid JWT token', desc: 'Empty JWT' });

  try {
    const decodedJwt = jwt.decode(jwtToken, { complete: true });
    if (!decodedJwt) return $err({ msg: 'Invalid JWT token', desc: "Couldn't decode JWT token" });

    return $ok({ decodedJwt });
  } catch (error) {
    return $err({
      msg: 'Invalid JWT token',
      desc: `Decoding error: ${error instanceof Error ? error.message : typeof error === 'string' ? error : String(error)}`,
    });
  }
}

export function $getExpiry(jwtToken: string): Result<{ clientId: string; exp: number }> {
  const { decodedJwt, error } = $decodeJwt(jwtToken);
  if (error) return $err(error);

  if (typeof decodedJwt.payload === 'string') {
    return $err({ msg: 'Invalid JWT token', desc: "Couldn't get the JWT payload" });
  }

  const clientId = decodedJwt.payload.aud;
  if (typeof clientId !== 'string')
    return $err({
      msg: 'Invalid JWT token',
      desc: `Invalid audience (aud) claim, payload: ${JSON.stringify(decodedJwt.payload)}`,
    });

  const exp = decodedJwt.payload.exp;
  if (typeof exp !== 'number')
    return $err({
      msg: 'Invalid JWT token',
      desc: `Invalid expiration (exp) claim, payload: ${JSON.stringify(decodedJwt.payload)}`,
    });

  return $ok({ clientId, exp });
}

export function $getKeyId(jwtToken: string): Result<{ kid: string; tenantId: string }> {
  const { decodedJwt, error } = $decodeJwt(jwtToken);
  if (error) return $err(error);

  const kid = decodedJwt.header.kid;
  if (typeof kid !== 'string')
    return $err({
      msg: 'Invalid JWT token',
      desc: `Invalid key ID (kid) claim, header: ${JSON.stringify(decodedJwt.header)}`,
    });

  if (typeof decodedJwt.payload === 'string') {
    return $err({ msg: 'Invalid JWT token', desc: "Couldn't get the JWT payload" });
  }

  const tenantId = decodedJwt.payload.tid;
  if (typeof tenantId !== 'string')
    return $err({
      msg: 'Invalid JWT token',
      desc: `Invalid tenant ID (tid) claim, payload: ${JSON.stringify(decodedJwt.payload)}`,
    });

  return $ok({ kid, tenantId });
}

export function $getClientId(jwtToken: string): Result<{ clientId: string }> {
  const { decodedJwt, error } = $decodeJwt(jwtToken);
  if (error) return $err(error);

  if (typeof decodedJwt.payload === 'string') {
    return $err({ msg: 'Invalid JWT token', desc: "Couldn't get the JWT payload" });
  }

  const clientId = decodedJwt.payload.aud;

  if (typeof clientId !== 'string')
    return $err({
      msg: 'Invalid JWT token',
      desc: `Invalid audience (aud) claim, payload: ${JSON.stringify(decodedJwt.payload)}`,
    });

  return $ok({ clientId });
}
