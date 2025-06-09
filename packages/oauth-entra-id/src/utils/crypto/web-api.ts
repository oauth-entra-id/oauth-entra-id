import { Buffer } from 'node:buffer';
import type { webcrypto } from 'node:crypto';
import { $err, $ok, type Result } from '~/error';
import { $isString } from '../zod';
import { FORMAT, WEB_API_ALGORITHM } from './encrypt';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function $generateWebApiUuid(): Result<{ uuid: string }> {
  try {
    return $ok({ uuid: crypto.randomUUID() });
  } catch (error) {
    return $err('crypto_error', {
      error: 'Failed to generate UUID',
      description: error instanceof Error ? error.message : String(error),
      status: 500,
    });
  }
}

export function $isWebApiKey(key: unknown): key is webcrypto.CryptoKey {
  return (
    key !== null &&
    key !== undefined &&
    typeof key === 'object' &&
    'type' in key &&
    typeof key.type === 'string' &&
    'algorithm' in key &&
    typeof key.algorithm === 'object' &&
    'extractable' in key &&
    typeof key.extractable === 'boolean' &&
    'usages' in key &&
    Array.isArray(key.usages) &&
    key.usages.every((usage) => typeof usage === 'string')
  );
}

export async function $createWebApiSecretKey(
  key: string | webcrypto.CryptoKey,
): Promise<Result<{ newSecretKey: webcrypto.CryptoKey }>> {
  if (typeof key === 'string') {
    if (!$isString(key)) {
      return $err('nullish_value', { error: 'Invalid secret key', description: 'Empty key for webApi', status: 500 });
    }
    try {
      const hashedKey = await crypto.subtle.digest('SHA-256', encoder.encode(key));
      const newSecretKey = await crypto.subtle.importKey('raw', hashedKey, { name: WEB_API_ALGORITHM }, true, [
        'encrypt',
        'decrypt',
      ]);
      return $ok({ newSecretKey: newSecretKey });
    } catch (error) {
      return $err('crypto_error', {
        error: 'Failed to create secret key',
        description: error instanceof Error ? error.message : String(error),
        status: 500,
      });
    }
  }

  if (!$isWebApiKey(key)) {
    return $err('misconfiguration', { error: 'Invalid secret key', description: 'Expected a CryptoKey' });
  }
  return $ok({ newSecretKey: key });
}

export async function $webApiEncrypt(
  data: string,
  secretKey: webcrypto.CryptoKey,
): Promise<Result<{ iv: string; encryptedWithTag: string }>> {
  try {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encryptedWithTag = await crypto.subtle.encrypt(
      { name: WEB_API_ALGORITHM, iv: iv },
      secretKey,
      encoder.encode(data),
    );
    return $ok({
      iv: Buffer.from(iv).toString(FORMAT),
      encryptedWithTag: Buffer.from(encryptedWithTag).toString(FORMAT),
    });
  } catch (error) {
    return $err('crypto_error', {
      error: 'Invalid data',
      description: `Failed to encrypt data: ${data}, ${error instanceof Error ? error.message : String(error)}`,
    });
  }
}

export async function $webApiDecrypt(
  iv: string,
  encryptedWithTag: string,
  secretKey: webcrypto.CryptoKey,
): Promise<Result<{ result: string }>> {
  try {
    const decrypted = await crypto.subtle.decrypt(
      { name: WEB_API_ALGORITHM, iv: Buffer.from(iv, FORMAT) },
      secretKey,
      Buffer.from(encryptedWithTag, FORMAT),
    );

    return $ok({ result: decoder.decode(decrypted) });
  } catch (error) {
    return $err('crypto_error', {
      error: 'Invalid data',
      description: `Failed to decrypt data: ${encryptedWithTag}, ${error instanceof Error ? error.message : String(error)}`,
    });
  }
}
