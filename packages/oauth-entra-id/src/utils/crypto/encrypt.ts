import { Buffer } from 'node:buffer';
import { webcrypto } from 'node:crypto';
import { $err, $ok, type Result } from '~/error';
import { $parseToObj, $stringifyObj } from './objects';

const ALGORITHM = 'AES-GCM';
export const FORMAT = 'base64url';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export async function $createSecretKey(
  key: string | webcrypto.CryptoKey,
): Promise<Result<{ newSecretKey: webcrypto.CryptoKey }>> {
  if (typeof key === 'string') {
    if (key.trim().length === 0) {
      return $err('nullish_value', { error: 'Invalid secret key', description: 'Empty string', status: 500 });
    }
    try {
      const hashedKey = await crypto.subtle.digest('SHA-256', encoder.encode(key));
      const newSecretKey = await crypto.subtle.importKey('raw', hashedKey, { name: ALGORITHM }, true, [
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

  if (key) {
    return $ok({ newSecretKey: key });
  }

  return $err('misconfiguration', {
    error: 'Invalid secret key',
    description: 'Expected a CryptoKey instance',
    status: 500,
  });
}

export async function $encrypt(
  data: string | null,
  key: string | webcrypto.CryptoKey,
): Promise<Result<{ encrypted: string; newSecretKey: webcrypto.CryptoKey }>> {
  if (!data || data.trim().length === 0) {
    return $err('nullish_value', { error: 'Invalid data', description: 'Empty string' });
  }

  const { newSecretKey, error } = await $createSecretKey(key);
  if (error) return $err(error);

  try {
    const iv = webcrypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt({ name: ALGORITHM, iv: iv }, newSecretKey, encoder.encode(data));
    return $ok({
      encrypted: `${Buffer.from(encrypted).toString(FORMAT)}.${Buffer.from(iv).toString(FORMAT)}.`,
      newSecretKey: newSecretKey,
    });
  } catch (error) {
    return $err('crypto_error', {
      error: 'Failed to generate IV',
      description: `Input: ${data}, ${error instanceof Error ? error.message : String(error)}`,
    });
  }
}

export async function $decrypt(
  encrypted: string | null,
  key: string | webcrypto.CryptoKey,
): Promise<Result<{ result: string; newSecretKey: webcrypto.CryptoKey }>> {
  if (!encrypted || encrypted.trim().length === 0) {
    return $err('nullish_value', { error: 'Invalid data', description: 'Empty string' });
  }
  if (!encrypted.includes('.')) {
    return $err('invalid_format', { error: 'Invalid encrypted data format', description: `Input: ${encrypted}` });
  }

  const { newSecretKey, error } = await $createSecretKey(key);
  if (error) return $err(error);

  try {
    const [encryptedData, iv] = encrypted.split('.');
    if (!encryptedData || !iv) {
      return $err('crypto_error', { error: 'Invalid encrypted data format', description: `Input: ${encryptedData}` });
    }

    const decryptedData = await crypto.subtle.decrypt(
      { name: ALGORITHM, iv: Buffer.from(iv, FORMAT) },
      newSecretKey,
      Buffer.from(encryptedData, FORMAT),
    );

    return $ok({ result: decoder.decode(decryptedData), newSecretKey: newSecretKey });
  } catch (error) {
    return $err('crypto_error', {
      error: 'Failed to decrypt data',
      description: `Input: ${encrypted}, ${error instanceof Error ? error.message : String(error)}`,
    });
  }
}

export async function $encryptObj(
  obj: Record<string, unknown> | null,
  key: string | webcrypto.CryptoKey,
): Promise<Result<{ encrypted: string; newSecretKey: webcrypto.CryptoKey }>> {
  const { result, error } = $stringifyObj(obj);
  if (error) return $err(error);
  return await $encrypt(result, key);
}

export async function $decryptObj(
  encryptedData: string | null,
  key: string | webcrypto.CryptoKey,
): Promise<Result<{ result: Record<string, unknown>; newSecretKey: webcrypto.CryptoKey }>> {
  const { result: decryptedResult, newSecretKey, error: decryptError } = await $decrypt(encryptedData, key);
  if (decryptError) return $err(decryptError);
  const { result, error } = $parseToObj(decryptedResult);
  if (error) return $err(error);
  return $ok({ result, newSecretKey });
}
