import jwt from 'jsonwebtoken';
import type { JwksClient } from 'jwks-rsa';
import { $err, $ok, type Result } from '~/error';
import type { Azure } from '~/types';
import { $isString } from '../zod';

export async function $verifyJwt({
  jwksClient,
  azure,
  jwtToken,
}: {
  jwksClient: JwksClient;
  azure: { clientId: string; tenantId: string };
  jwtToken: string;
}): Promise<Result<{ payload: jwt.JwtPayload }>> {
  const kid = $getKid(jwtToken);
  if (kid.error) return $err('jwt_error', { error: 'Unauthorized', description: kid.error.description, status: 401 });

  try {
    const publicKey = await $getPublicKey(jwksClient, kid.result);

    const decodedJwt = jwt.verify(jwtToken, publicKey, {
      algorithms: ['RS256'],
      audience: azure.clientId,
      issuer: `https://login.microsoftonline.com/${azure.tenantId}/v2.0`,
      complete: true,
    });

    if (typeof decodedJwt.payload === 'string') {
      return $err('jwt_error', { error: 'Unauthorized', description: 'Payload is a string', status: 401 });
    }

    return $ok({ payload: decodedJwt.payload });
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

export function $getAudAndExp(jwtToken: string): Result<{ aud: string; exp: number }> {
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

export function $getKid(jwtToken: string): Result<string> {
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
