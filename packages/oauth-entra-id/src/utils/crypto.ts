import crypto, { type KeyObject } from 'node:crypto';
import jwt from 'jsonwebtoken';
import { $err, $ok, type Result } from '~/error';
import type { InjectedData } from '~/types';
import { zAccessTokenStructure } from './zod';

const ALGORITHM = 'aes-256-gcm';
const ENCODE_FORMAT = 'base64url';

const $isEmptyString = (str: string) => str.trim().length === 0;

export function $encode(str: string): Result<string> {
  if ($isEmptyString(str)) return $err('nullish_value', { error: 'Invalid data', description: 'Empty string' });

  try {
    return $ok(Buffer.from(str, 'utf8').toString(ENCODE_FORMAT));
  } catch {
    return $err('format', { error: 'Invalid base64url format', description: `Input: ${str}` });
  }
}

export function $decode(str: string): Result<string> {
  //TODO: add regex for base64url
  if ($isEmptyString(str)) return $err('nullish_value', { error: 'Invalid data', description: 'Empty string' });

  try {
    return $ok(Buffer.from(str, ENCODE_FORMAT).toString('utf8'));
  } catch {
    return $err('format', { error: 'Invalid base64url format', description: `Input: ${str}` });
  }
}

function $createSecretKey(key: string): Result<KeyObject> {
  if ($isEmptyString(key)) {
    return $err('nullish_value', { error: 'Invalid secret key', description: 'Empty string' }, 500);
  }

  try {
    const hashedKey = crypto.createHash('sha256').update(key).digest();
    return $ok(crypto.createSecretKey(hashedKey));
  } catch {
    return $err('cryptography', { error: 'Failed to create secret key', description: `Input: ${key}` }, 500);
  }
}

export function $createSecretKeys(key: string): Result<{ at: KeyObject; rt: KeyObject; state: KeyObject }> {
  if ($isEmptyString(key)) {
    return $err('nullish_value', { error: 'Invalid secret key', description: 'Empty string' }, 500);
  }

  const atSecretKey = $createSecretKey(`access-token-${key}`);
  if (atSecretKey.error) return atSecretKey;

  const rtSecretKey = $createSecretKey(`refresh-token-${key}`);
  if (rtSecretKey.error) return rtSecretKey;

  const stateSecretKey = $createSecretKey(`state-${key}`);
  if (stateSecretKey.error) return stateSecretKey;

  return $ok({ at: atSecretKey.result, rt: rtSecretKey.result, state: stateSecretKey.result });
}

export function $encrypt(str: string, secretKey: KeyObject): Result<string> {
  if ($isEmptyString(str)) return $err('nullish_value', { error: 'Invalid data', description: 'Empty string' });

  try {
    const iv = crypto.randomBytes(12);

    const cipher = crypto.createCipheriv(ALGORITHM, secretKey, iv);
    const encrypted = Buffer.concat([cipher.update(str, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();

    return $ok(`${iv.toString(ENCODE_FORMAT)}.${encrypted.toString(ENCODE_FORMAT)}.${tag.toString(ENCODE_FORMAT)}.`);
  } catch {
    return $err('cryptography', { error: 'Encryption failed', description: `Input: ${str}` });
  }
}

export function $decrypt(encrypted: string, secretKey: KeyObject): Result<string> {
  if ($isEmptyString(encrypted)) return $err('nullish_value', { error: 'Invalid data', description: 'Empty string' });

  if (!encrypted.includes('.')) return $err('format', { error: 'Invalid data', description: 'Missing dot separator' });

  try {
    const [iv, encryptedData, tag] = encrypted.split('.');
    if (!iv || !encryptedData || !tag) return $err('format', { error: 'Invalid encrypted data format' });

    const decipher = crypto.createDecipheriv(ALGORITHM, secretKey, Buffer.from(iv, ENCODE_FORMAT));
    decipher.setAuthTag(Buffer.from(tag, ENCODE_FORMAT));

    return $ok(
      Buffer.concat([decipher.update(Buffer.from(encryptedData, ENCODE_FORMAT)), decipher.final()]).toString('utf8'),
    );
  } catch {
    return $err('cryptography', { error: 'Invalid encrypted data format', description: `Input: ${encrypted}` });
  }
}

export function $encryptObj(obj: Record<string, unknown> | null, secretKey: KeyObject): Result<string> {
  if (!obj) return $err('nullish_value', { error: 'Invalid data' });

  try {
    return $encrypt(JSON.stringify(obj), secretKey);
  } catch {
    return $err('serialization', { error: 'Encryption failed', description: 'Failed to stringify object' });
  }
}

export function $decryptObj(data: string | null, secretKey: KeyObject): Result<Record<string, unknown>> {
  if (!data) return $err('nullish_value', { error: 'Invalid data' });
  const decryptedData = $decrypt(data, secretKey);
  if (decryptedData.error) return decryptedData;

  try {
    return JSON.parse(decryptedData.result);
  } catch {
    return $err('serialization', {
      error: 'Invalid data',
      description: `Failed to parse JSON, input: ${decryptedData.result}`,
    });
  }
}

export function $encryptToken(
  tokenType: 'accessToken' | 'refreshToken',
  value: string | null,
  secretKey: KeyObject,
): Result<string> {
  if (!value) return $err('nullish_value', { error: 'Invalid data' });

  const tokenValue = tokenType === 'accessToken' ? $encryptObj({ at: value }, secretKey) : $encrypt(value, secretKey);
  if (tokenValue.error) return tokenValue;

  return $ok(tokenValue.result);
}

export function $decryptToken(
  tokenType: 'accessToken' | 'refreshToken',
  encryptedToken: string | null,
  secretKey: KeyObject,
): Result<{ rawToken: string; injectedData?: InjectedData }> {
  if (!encryptedToken || $isEmptyString(encryptedToken)) return $err('nullish_value', { error: 'Invalid data' });

  if (tokenType === 'accessToken') {
    const accessTokenObj = $decryptObj(encryptedToken, secretKey);
    if (accessTokenObj.error) return accessTokenObj;

    const accessToken = zAccessTokenStructure.safeParse(accessTokenObj.result);
    if (accessToken.error) return $err('format', { error: 'Invalid data', description: `Input: ${encryptedToken}` });

    return $ok({ rawToken: accessToken.data.at, injectedData: accessToken.data.inj });
  }

  const refreshToken = $decrypt(encryptedToken, secretKey);
  if (refreshToken.error) return refreshToken;

  return $ok({ rawToken: refreshToken.result });
}

function $decodeJwt(jwtToken: string): Result<jwt.Jwt> {
  if ($isEmptyString(jwtToken)) return $err('nullish_value', { error: 'Invalid data', description: 'Empty string' });

  try {
    const decoded = jwt.decode(jwtToken, { complete: true });
    if (!decoded) return $err('jwt_error', { error: 'Invalid JWT token', description: "Couldn't decode JWT token" });
    return $ok(decoded);
  } catch {
    return $err('jwt_error', { error: 'Invalid JWT token', description: "Couldn't decode JWT token" });
  }
}

export function $getAud(jwtToken: string): Result<string> {
  const decodedJwt = $decodeJwt(jwtToken);
  if (decodedJwt.error) return decodedJwt;

  if (typeof decodedJwt.result.payload === 'string') {
    return $err('jwt_error', { error: 'Invalid JWT token', description: "Couldn't get the JWT payload" });
  }

  const aud = decodedJwt.result.payload.aud;
  if (typeof aud !== 'string')
    return $err('jwt_error', {
      error: 'Invalid JWT token',
      description: `Invalid audience (aud) claim, payload: ${JSON.stringify(decodedJwt.result.payload)}`,
    });

  return $ok(aud);
}

export function $getKid(jwtToken: string): Result<string> {
  const decodedJwt = $decodeJwt(jwtToken);
  if (decodedJwt.error) return decodedJwt;

  const kid = decodedJwt.result.header.kid;
  if (typeof kid !== 'string')
    return $err('jwt_error', {
      error: 'Invalid JWT token',
      description: `Invalid key ID (kid) claim, header: ${JSON.stringify(decodedJwt.result.header)}`,
    });

  return $ok(kid);
}
