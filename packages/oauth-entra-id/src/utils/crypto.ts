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
    return $err('invalid_format', { error: 'Invalid base64url format', description: `Input: ${str}` });
  }
}

export function $decode(str: string): Result<string> {
  //TODO: add regex for base64url
  if ($isEmptyString(str)) return $err('nullish_value', { error: 'Invalid data', description: 'Empty string' });

  try {
    return $ok(Buffer.from(str, ENCODE_FORMAT).toString('utf8'));
  } catch {
    return $err('invalid_format', { error: 'Invalid base64url format', description: `Input: ${str}` });
  }
}

export function $createSecretKey(key: string): Result<KeyObject> {
  if ($isEmptyString(key)) {
    return $err('nullish_value', { error: 'Invalid secret key', description: 'Empty string' }, 500);
  }

  try {
    const hashedKey = crypto.createHash('sha256').update(key).digest();
    return $ok(crypto.createSecretKey(hashedKey));
  } catch {
    return $err('crypto_error', { error: 'Failed to create secret key', description: `Input: ${key}` }, 500);
  }
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
    return $err('crypto_error', { error: 'Encryption failed', description: `Input: ${str}` });
  }
}

export function $decrypt(encrypted: string, secretKey: KeyObject): Result<string> {
  if ($isEmptyString(encrypted)) return $err('nullish_value', { error: 'Invalid data', description: 'Empty string' });

  if (!encrypted.includes('.')) {
    return $err('invalid_format', { error: 'Invalid data', description: 'Missing dot separator' });
  }

  try {
    const [iv, encryptedData, tag] = encrypted.split('.');
    if (!iv || !encryptedData || !tag) return $err('invalid_format', { error: 'Invalid encrypted data format' });

    const decipher = crypto.createDecipheriv(ALGORITHM, secretKey, Buffer.from(iv, ENCODE_FORMAT));
    decipher.setAuthTag(Buffer.from(tag, ENCODE_FORMAT));

    return $ok(
      Buffer.concat([decipher.update(Buffer.from(encryptedData, ENCODE_FORMAT)), decipher.final()]).toString('utf8'),
    );
  } catch {
    return $err('crypto_error', { error: 'Invalid encrypted data format', description: `Input: ${encrypted}` });
  }
}

export function $encryptObj(obj: Record<string, unknown> | null, secretKey: KeyObject): Result<string> {
  if (!obj) return $err('nullish_value', { error: 'Invalid data' });

  try {
    return $encrypt(JSON.stringify(obj), secretKey);
  } catch {
    return $err('invalid_format', { error: 'Encryption failed', description: 'Failed to stringify object' });
  }
}

export function $decryptObj(data: string | null, secretKey: KeyObject): Result<Record<string, unknown>> {
  if (!data) return $err('nullish_value', { error: 'Invalid data' });
  const { result: decrypted, error: decryptedError } = $decrypt(data, secretKey);
  if (decryptedError) return $err(decryptedError);

  try {
    return JSON.parse(decrypted);
  } catch {
    return $err('invalid_format', { error: 'Invalid data', description: `Failed to parse JSON, input: ${decrypted}` });
  }
}

export function $encryptToken(
  tokenType: 'accessToken' | 'refreshToken',
  value: string | null,
  secretKey: KeyObject,
  injectedData?: InjectedData,
): Result<string> {
  if (!value) return $err('nullish_value', { error: 'Invalid data' });

  const { result: token, error: tokenError } =
    tokenType === 'accessToken' ? $encryptObj({ at: value, inj: injectedData }, secretKey) : $encrypt(value, secretKey);

  if (tokenError) return $err(tokenError);

  return $ok(token);
}

export function $decryptToken(
  tokenType: 'accessToken' | 'refreshToken',
  encryptedToken: string | null,
  secretKey: KeyObject,
): Result<{ rawToken: string; injectedData?: InjectedData }> {
  if (!encryptedToken || $isEmptyString(encryptedToken)) return $err('nullish_value', { error: 'Invalid data' });

  if (tokenType === 'accessToken') {
    const { result: decryptedAt, error: decryptedAtError } = $decryptObj(encryptedToken, secretKey);
    if (decryptedAtError) return $err(decryptedAtError);

    const { data: atObj, error: atObjError } = zAccessTokenStructure.safeParse(decryptedAt);
    if (atObjError) {
      return $err('invalid_format', { error: 'Invalid data', description: 'Invalid access token structure' });
    }

    return $ok({ rawToken: atObj.at, injectedData: atObj.inj });
  }

  const { result: rt, error: rtError } = $decrypt(encryptedToken, secretKey);
  if (rtError) return $err(rtError);

  return $ok({ rawToken: rt });
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
  const { result: decodedJwt, error: decodeJwtError } = $decodeJwt(jwtToken);
  if (decodeJwtError) return $err(decodeJwtError);

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
  const { result: decodedJwt, error: decodeJwtError } = $decodeJwt(jwtToken);
  if (decodeJwtError) return $err(decodeJwtError);

  const kid = decodedJwt.header.kid;
  if (typeof kid !== 'string')
    return $err('jwt_error', {
      error: 'Invalid JWT token',
      description: `Invalid key ID (kid) claim, header: ${JSON.stringify(decodedJwt.header)}`,
    });

  return $ok(kid);
}
