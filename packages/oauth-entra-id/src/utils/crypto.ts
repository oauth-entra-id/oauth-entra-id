import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import { $err, $ok, type Result } from '~/error';

const ALGORITHM = 'aes-256-gcm';
const FORMAT = 'base64url';

export const $encode = (str: string) => Buffer.from(str, 'utf8').toString('base64url');
export const $decode = (str: string) => Buffer.from(str, 'base64url').toString('utf8');
export const $hash = (str: string): Buffer => crypto.createHash('sha256').update(str).digest();
export const $createSecretKey = (key: string): crypto.KeyObject => crypto.createSecretKey($hash(key));

export function $encrypt(data: string, secretKey: crypto.KeyObject): Result<string> {
  try {
    const iv = crypto.randomBytes(12);

    const cipher = crypto.createCipheriv(ALGORITHM, secretKey, iv);
    const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();

    return $ok(`${iv.toString(FORMAT)}.${encrypted.toString(FORMAT)}.${tag.toString(FORMAT)}.`);
  } catch {
    return $err('encrypt_error', { error: 'Encryption failed' });
  }
}

export function $decrypt(encrypted: string, secretKey: crypto.KeyObject): Result<string> {
  try {
    const [ivBase64, encryptedBase64, tagBase64] = encrypted.split('.');
    if (!ivBase64 || !encryptedBase64 || !tagBase64) {
      return $err('decrypt_error', { error: 'Invalid encrypted data format' });
    }

    const decipher = crypto.createDecipheriv(ALGORITHM, secretKey, Buffer.from(ivBase64, FORMAT));
    decipher.setAuthTag(Buffer.from(tagBase64, FORMAT));

    return $ok(
      Buffer.concat([decipher.update(Buffer.from(encryptedBase64, FORMAT)), decipher.final()]).toString('utf8'),
    );
  } catch {
    return $err('decrypt_error', { error: 'Invalid encrypted data format', description: `Input: ${encrypted}` });
  }
}

export function $encryptObj(data: Record<string, unknown> | null, secretKey: crypto.KeyObject): Result<string> {
  if (!data) return $err('null_value', { error: 'Invalid data' });
  return $encrypt(JSON.stringify(data), secretKey);
}

export function $decryptObj(data: string | null, secretKey: crypto.KeyObject): Result<Record<string, unknown>> {
  if (!data) return $err('null_value', { error: 'Invalid data' });
  const decryptedData = $decrypt(data, secretKey);
  if (!decryptedData.success) return decryptedData;
  try {
    return JSON.parse(decryptedData.result);
  } catch {
    return $err('decrypt_error', { error: 'Invalid JSON format' }, 500);
  }
}

export function $getAud(jwtToken: string): Result<string> {
  const payload = jwt.decode(jwtToken, { json: true });
  if (!payload) return $err('jwt_error', { error: 'Invalid JWT token' });

  const aud = payload.aud;
  if (typeof aud !== 'string')
    return $err('jwt_error', { error: 'Invalid JWT token', description: 'Invalid audience (aud) claim' });

  return $ok(aud);
}
