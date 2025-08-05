import {
  isNodeKey,
  isWebApiKey,
  type NodeKey,
  newNodeSecretKey,
  newNodeUuid,
  newWebSecretKey,
  newWebUuid,
  nodeDecrypt,
  nodeEncrypt,
  parseToObj,
  stringifyObj,
  type WebApiKey,
  webDecrypt,
  webEncrypt,
} from 'cipher-kit';
import { $err, $ok } from '~/error';
import type { Result } from '~/exports';
import type { CryptoType } from '~/types';
import { $isStr } from './zod';

export function $newUuid(cryptoType: CryptoType): Result<{ uuid: string }> {
  const uuid = cryptoType === 'node' ? newNodeUuid() : newWebUuid();
  if (uuid.error) return $err('crypto_error', { error: 'Failed to generate UUID', description: uuid.error.message });
  return $ok({ uuid: uuid.result });
}

export function $newSecretKey(cryptoType: CryptoType, key: string): Result<{ newSecretKey: string | NodeKey }> {
  if (cryptoType === 'web-api') return $ok({ newSecretKey: key });

  const { secretKey, error } = newNodeSecretKey(key);
  if (error) return $err('crypto_error', { error: 'Failed to create secret key', description: error.message });
  return $ok({ newSecretKey: secretKey });
}

export function $newSecretKeys(
  cryptoType: CryptoType,
  keys: { accessToken: string; refreshToken: string; state: string; ticket: string },
): Result<{
  secretKeys: {
    accessToken: string | NodeKey;
    refreshToken: string | NodeKey;
    state: string | NodeKey;
    ticket: string | NodeKey;
  };
}> {
  if (cryptoType === 'web-api') {
    return $ok({ secretKeys: keys });
  }

  const { secretKey: atKey, error: atError } = newNodeSecretKey(keys.accessToken);
  if (atError) {
    return $err('crypto_error', { error: 'Failed to create access token key', description: atError.message });
  }

  const { secretKey: rtKey, error: rtError } = newNodeSecretKey(keys.refreshToken);
  if (rtError) {
    return $err('crypto_error', { error: 'Failed to create refresh token key', description: rtError.message });
  }

  const { secretKey: stateKey, error: stateError } = newNodeSecretKey(keys.state);
  if (stateError) {
    return $err('crypto_error', { error: 'Failed to create state key', description: stateError.message });
  }

  const { secretKey: ticketKey, error: ticketError } = newNodeSecretKey(keys.ticket);
  if (ticketError) {
    return $err('crypto_error', { error: 'Failed to create ticket key', description: ticketError.message });
  }

  return $ok({ secretKeys: { accessToken: atKey, refreshToken: rtKey, state: stateKey, ticket: ticketKey } });
}

export async function $encrypt(
  cryptoType: CryptoType,
  data: string | null,
  key: string | WebApiKey | NodeKey,
): Promise<Result<{ encrypted: string; newSecretKey: WebApiKey | undefined }>> {
  if (!data) return $err('nullish_value', { error: 'Invalid data', description: 'Empty string to encrypt' });
  if (cryptoType === 'node') {
    if (!$isStr(key) && !isNodeKey(key)) {
      return $err('invalid_format', { error: 'Invalid key type', description: 'Expected NodeKey or string' });
    }
    const { secretKey, error: secretKeyError } = newNodeSecretKey(key);
    if (secretKeyError) {
      return $err('crypto_error', { error: 'Failed to create Node secret key', description: secretKeyError.message });
    }

    const encrypted = nodeEncrypt(data, secretKey);
    if (encrypted.error) {
      return $err('crypto_error', { error: 'Encryption failed', description: encrypted.error.message });
    }
    return $ok({ encrypted: encrypted.result, newSecretKey: undefined });
  }

  if (!$isStr(key) && !isWebApiKey(key)) {
    return $err('invalid_format', { error: 'Invalid key type', description: 'Expected string or WebApiKey' });
  }

  const { secretKey, error: secretKeyError } = await newWebSecretKey(key);
  if (secretKeyError) {
    return $err('crypto_error', { error: 'Failed to create Web API secret key', description: secretKeyError.message });
  }
  const encrypted = await webEncrypt(data, secretKey);
  if (encrypted.error) {
    return $err('crypto_error', { error: 'Encryption failed', description: encrypted.error.message });
  }
  return $ok({ encrypted: encrypted.result, newSecretKey: secretKey });
}

export async function $decrypt(
  cryptoType: CryptoType,
  encrypted: string | null,
  key: string | WebApiKey | NodeKey,
): Promise<Result<{ result: string; newSecretKey: WebApiKey | undefined }>> {
  if (!encrypted) return $err('nullish_value', { error: 'Invalid data', description: 'Empty string to decrypt' });
  if (cryptoType === 'node') {
    if (!$isStr(key) && !isNodeKey(key)) {
      return $err('invalid_format', { error: 'Invalid key type', description: 'Expected NodeKey or string' });
    }

    const { secretKey, error: secretKeyError } = newNodeSecretKey(key);
    if (secretKeyError) {
      return $err('crypto_error', { error: 'Failed to create Node secret key', description: secretKeyError.message });
    }

    const decrypted = nodeDecrypt(encrypted, secretKey);
    if (decrypted.error) {
      return $err('crypto_error', { error: 'Decryption failed', description: decrypted.error.message });
    }
    return $ok({ result: decrypted.result, newSecretKey: undefined });
  }
  if (!$isStr(key) && !isWebApiKey(key)) {
    return $err('invalid_format', { error: 'Invalid key type', description: 'Expected string or WebApiKey' });
  }

  const { secretKey, error: secretKeyError } = await newWebSecretKey(key);
  if (secretKeyError) {
    return $err('crypto_error', { error: 'Failed to create Web API secret key', description: secretKeyError.message });
  }
  const decrypted = await webDecrypt(encrypted, secretKey);
  if (decrypted.error) {
    return $err('crypto_error', { error: 'Decryption failed', description: decrypted.error.message });
  }
  return $ok({ result: decrypted.result, newSecretKey: secretKey });
}

export async function $encryptObj(
  cryptoType: CryptoType,
  obj: Record<string, unknown> | null,
  key: string | WebApiKey | NodeKey,
): Promise<Result<{ encrypted: string; newSecretKey: WebApiKey | undefined }>> {
  if (!obj) return $err('nullish_value', { error: 'Invalid data', description: 'Empty object to encrypt' });
  const { result, error } = stringifyObj(obj);
  if (error) return $err('crypto_error', { error: 'Failed to stringify object', description: error.message });
  return await $encrypt(cryptoType, result, key);
}

export async function $decryptObj(
  cryptoType: CryptoType,
  encrypted: string | null,
  key: string | WebApiKey | NodeKey,
): Promise<Result<{ result: Record<string, unknown>; newSecretKey: WebApiKey | undefined }>> {
  if (!encrypted) return $err('nullish_value', { error: 'Invalid data', description: 'Empty string to decrypt' });
  const decrypted = await $decrypt(cryptoType, encrypted, key);
  if (decrypted.error) return decrypted;
  const { result, error } = parseToObj(decrypted.result);
  if (error) return $err('crypto_error', { error: 'Failed to parse object', description: error.message });
  return $ok({ result, newSecretKey: decrypted.newSecretKey });
}
