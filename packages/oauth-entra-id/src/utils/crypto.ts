import { Buffer } from 'node:buffer';
import { webcrypto } from 'node:crypto';
import jwt from 'jsonwebtoken';
import { $err, $ok, type Result } from '~/error';

const ALGORITHM = 'AES-GCM';
const FORMAT = 'base64url';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export type SecretKey = string | webcrypto.CryptoKey;

export async function $createSecretKey(
  key: string | webcrypto.CryptoKey,
): Promise<Result<{ secretKey: webcrypto.CryptoKey }>> {
  if (typeof key === 'string') {
    if (key.trim().length === 0) {
      return $err('nullish_value', { error: 'Invalid secret key', description: 'Empty string', status: 500 });
    }
    try {
      const hashedKey = await crypto.subtle.digest('SHA-256', encoder.encode(key));
      const secretKey = await crypto.subtle.importKey('raw', hashedKey, { name: ALGORITHM }, true, [
        'encrypt',
        'decrypt',
      ]);
      return $ok({ secretKey });
    } catch (error) {
      return $err('crypto_error', { error: 'Failed to create secret key', status: 500 });
    }
  }

  if (key) {
    return $ok({ secretKey: key });
  }

  return $err('misconfiguration', {
    error: 'Invalid secret key',
    description: 'Expected a CryptoKey instance',
    status: 500,
  });
}

export async function $encrypt(
  data: string,
  key: string | webcrypto.CryptoKey,
): Promise<Result<{ encrypted: string; secretKey: webcrypto.CryptoKey }>> {
  if (data.trim().length === 0) {
    return $err('nullish_value', { error: 'Invalid data', description: 'Empty string' });
  }

  const { secretKey, error } = await $createSecretKey(key);
  if (error) return $err(error);

  try {
    const iv = webcrypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt({ name: ALGORITHM, iv: iv }, secretKey, encoder.encode(data));
    return $ok({
      encrypted: `${Buffer.from(encrypted).toString(FORMAT)}.${Buffer.from(iv).toString(FORMAT)}.`,
      secretKey,
    });
  } catch (error) {
    return $err('crypto_error', { error: 'Failed to generate IV', description: `Input: ${data}` });
  }
}

export async function $decrypt(
  encrypted: string,
  key: string | webcrypto.CryptoKey,
): Promise<Result<{ data: string; secretKey: webcrypto.CryptoKey }>> {
  if (encrypted.trim().length === 0) {
    return $err('nullish_value', { error: 'Invalid data', description: 'Empty string' });
  }
  if (!encrypted.includes('.')) {
    return $err('invalid_format', { error: 'Invalid encrypted data format', description: `Input: ${encrypted}` });
  }

  const { secretKey, error } = await $createSecretKey(key);
  if (error) return $err(error);

  try {
    const [encryptedData, iv] = encrypted.split('.');
    if (!encryptedData || !iv) {
      return $err('crypto_error', { error: 'Invalid encrypted data format', description: `Input: ${encryptedData}` });
    }

    const decryptedData = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: Buffer.from(iv, FORMAT) },
      secretKey,
      Buffer.from(encryptedData, FORMAT),
    );

    return $ok({ data: decoder.decode(decryptedData), secretKey });
  } catch (error) {
    return $err('crypto_error', { error: 'Failed to decrypt data', description: `Input: ${encrypted}` });
  }
}

export async function $encryptObj(
  obj: Record<string, unknown> | null,
  key: string | webcrypto.CryptoKey,
): Promise<Result<{ encrypted: string; secretKey: webcrypto.CryptoKey }>> {
  if (!obj) return $err('nullish_value', { error: 'Invalid data' });

  try {
    return await $encrypt(JSON.stringify(obj), key);
  } catch {
    return $err('invalid_format', { error: 'Encryption failed', description: 'Failed to stringify object' });
  }
}

export async function $decryptObj(
  encryptedData: string | null,
  key: string | webcrypto.CryptoKey,
): Promise<Result<{ data: string; secretKey: webcrypto.CryptoKey }>> {
  if (!encryptedData) return $err('nullish_value', { error: 'Invalid data' });
  const { data, secretKey, error } = await $decrypt(encryptedData, key);
  if (error) return $err(error);

  try {
    return $ok({ data: JSON.parse(data), secretKey });
  } catch {
    return $err('invalid_format', { error: 'Invalid data', description: `Failed to parse JSON, input: ${data}` });
  }
}

function $decodeJwt(jwtToken: string): Result<{ decodedJwt: jwt.Jwt }> {
  if (jwtToken.trim().length === 0) {
    return $err('nullish_value', { error: 'Invalid data', description: 'Empty string' });
  }

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
