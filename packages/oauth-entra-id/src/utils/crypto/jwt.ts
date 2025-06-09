import jwt from 'jsonwebtoken';
import { $err, $ok, type Result } from '~/error';
import { $isString } from '../zod';

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

export function $getAud(jwtToken: string): Result<string> {
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

  return $ok(aud);
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
