import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';

const ALGORITHM = 'aes-256-gcm';
const FORMAT = 'base64url';

export const encodeBase64 = (str: string) => Buffer.from(str, 'utf8').toString('base64url');
export const decodeBase64 = (str: string) => Buffer.from(str, 'base64url').toString('utf8');

export const hash = (str: string): Buffer => crypto.createHash('sha256').update(str).digest();
export const createSecretKey = (key: string): crypto.KeyObject => crypto.createSecretKey(hash(key));

export function encrypt(data: string, secretKey: crypto.KeyObject) {
  try {
    const iv = crypto.randomBytes(12);

    const cipher = crypto.createCipheriv(ALGORITHM, secretKey, iv);
    const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();

    return `${[iv, encrypted, tag].map((buffer) => buffer.toString(FORMAT)).join('.')}.`;
  } catch {
    throw new Error('Failed to encrypt');
  }
}

export function decrypt(encryptedData: string, secretKey: crypto.KeyObject) {
  try {
    const [ivBase64, encryptedBase64, tagBase64] = encryptedData.split('.');
    if (!ivBase64 || !encryptedBase64 || !tagBase64) throw new Error('Invalid decrypt data format');

    const decipher = crypto.createDecipheriv(ALGORITHM, secretKey, Buffer.from(ivBase64, FORMAT));
    decipher.setAuthTag(Buffer.from(tagBase64, FORMAT));

    const decrypted = Buffer.concat([decipher.update(Buffer.from(encryptedBase64, FORMAT)), decipher.final()]);
    return decrypted.toString('utf8');
  } catch {
    return null;
  }
}

export function encryptObject(data: Record<string, unknown>, secretKey: crypto.KeyObject): string {
  try {
    return encrypt(JSON.stringify(data), secretKey);
  } catch {
    throw new Error('Failed to encrypt object');
  }
}

export function decryptObject(data: string, secretKey: crypto.KeyObject): Record<string, unknown> | null {
  const decryptedData = decrypt(data, secretKey);
  if (!decryptedData) return null;
  try {
    return JSON.parse(decryptedData);
  } catch {
    return null;
  }
}

export function getAudFromJwt(jwtToken: string) {
  const payload = jwt.decode(jwtToken, { json: true });
  if (!payload) return null;

  const aud = payload.aud;
  if (typeof aud !== 'string') return null;

  return aud;
}
