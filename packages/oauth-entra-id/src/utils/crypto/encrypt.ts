import { $err, $ok, type Result } from '~/error';
import type { CryptoType, NodeCryptoKey, WebApiCryptoKey } from '~/types';
import { $isString, encryptedNodeRegex, encryptedWebApiRegex } from '../zod';
import { $createNodeSecretKey, $generateNodeUuid, $nodeDecrypt, $nodeEncrypt } from './node';
import { $parseToObj, $stringifyObj } from './objects';
import { $createWebApiSecretKey, $generateWebApiUuid, $isWebApiKey, $webApiDecrypt, $webApiEncrypt } from './web-api';

export const FORMAT = 'base64url';
export const NODE_ALGORITHM = 'aes-256-gcm';
export const WEB_API_ALGORITHM = 'AES-GCM';

export function $generateUuid(cryptoType: CryptoType): Result<{ uuid: string }> {
  if (cryptoType === 'web-api') return $generateNodeUuid();
  return $generateWebApiUuid();
}

export function $createSecretKey(
  cryptoType: CryptoType,
  key: string,
): Result<{ newSecretKey: string | NodeCryptoKey }> {
  if (cryptoType === 'web-api') {
    return $ok({ newSecretKey: key });
  }

  const { newSecretKey, error } = $createNodeSecretKey(key);
  if (error) return $err(error);
  return $ok({ newSecretKey });
}

export function $createSecretKeys(
  cryptoType: CryptoType,
  keys: { accessToken: string; refreshToken: string; state: string; ticket: string },
): Result<{
  secretKeys: {
    accessToken: string | NodeCryptoKey;
    refreshToken: string | NodeCryptoKey;
    state: string | NodeCryptoKey;
    ticket: string | NodeCryptoKey;
  };
}> {
  if (cryptoType === 'web-api') {
    return $ok({ secretKeys: keys });
  }

  const atKey = $createNodeSecretKey(keys.accessToken);
  if (atKey.error) return $err(atKey.error);
  const rtKey = $createNodeSecretKey(keys.refreshToken);
  if (rtKey.error) return $err(rtKey.error);
  const stateKey = $createNodeSecretKey(keys.state);
  if (stateKey.error) return $err(stateKey.error);
  const ticketKey = $createNodeSecretKey(keys.ticket);
  if (ticketKey.error) return $err(ticketKey.error);

  return $ok({
    secretKeys: {
      accessToken: atKey.newSecretKey,
      refreshToken: rtKey.newSecretKey,
      state: stateKey.newSecretKey,
      ticket: ticketKey.newSecretKey,
    },
  });
}

export async function $encrypt(
  cryptoType: CryptoType,
  data: string | null,
  key: string | WebApiCryptoKey | NodeCryptoKey,
): Promise<Result<{ encrypted: string; newSecretKey: WebApiCryptoKey | undefined }>> {
  if (!$isString(data)) return $err('nullish_value', { error: 'Invalid data', description: 'Empty string to encrypt' });

  if (cryptoType === 'node') {
    if ($isWebApiKey(key)) {
      return $err('misconfiguration', { error: 'Invalid secret key', description: 'Expected a Node.js KeyObject' });
    }
    const { newSecretKey, error: secretKeyError } = $createNodeSecretKey(key);
    if (secretKeyError) return $err(secretKeyError);

    const { iv, encrypted, tag, error } = $nodeEncrypt(data, newSecretKey);
    if (error) return $err(error);
    return $ok({
      encrypted: `${iv}.${encrypted}.${tag}.`,
      newSecretKey: undefined,
    });
  }
  if (typeof key !== 'string' && !$isWebApiKey(key)) {
    return $err('misconfiguration', {
      error: 'Invalid secret key',
      description: 'Expected a Web Crypto API CryptoKey instance',
    });
  }
  const { newSecretKey, error: secretKeyError } = await $createWebApiSecretKey(key);
  if (secretKeyError) return $err(secretKeyError);

  const { iv, encryptedWithTag, error } = await $webApiEncrypt(data, newSecretKey);
  if (error) return $err(error);
  return $ok({
    encrypted: `${iv}.${encryptedWithTag}.`,
    newSecretKey,
  });
}

export async function $decrypt(
  cryptoType: CryptoType,
  encrypted: string | null,
  key: string | WebApiCryptoKey | NodeCryptoKey,
): Promise<Result<{ result: string; newSecretKey: WebApiCryptoKey | undefined }>> {
  if (!$isString(encrypted)) {
    return $err('nullish_value', { error: 'Invalid data', description: 'Empty string to decrypt' });
  }

  const parts = encrypted.split('.');
  if (cryptoType === 'node') {
    if (typeof key === 'string' || $isWebApiKey(key)) {
      return $err('misconfiguration', { error: 'Invalid secret key', description: 'Expected a Node.js KeyObject' });
    }

    if (!encryptedNodeRegex.test(encrypted)) {
      return $err('invalid_format', { error: 'Invalid data', description: 'Data does not match expected format' });
    }

    const [iv, encryptedData, tag] = parts as [string, string, string];

    const { result, error } = $nodeDecrypt(iv, encryptedData, tag, key);
    if (error) return $err(error);
    return $ok({ result, newSecretKey: undefined });
  }

  if (typeof key !== 'string' && !$isWebApiKey(key)) {
    return $err('misconfiguration', {
      error: 'Invalid secret key',
      description: 'Expected a Web Crypto API CryptoKey instance',
    });
  }

  const { newSecretKey, error: secretKeyError } = await $createWebApiSecretKey(key);
  if (secretKeyError) return $err(secretKeyError);

  if (!encryptedWebApiRegex.test(encrypted)) {
    return $err('invalid_format', { error: 'Invalid data', description: 'Data does not match expected format' });
  }

  const [iv, encryptedWithTag] = parts as [string, string];

  const { result, error } = await $webApiDecrypt(iv, encryptedWithTag, newSecretKey);
  if (error) return $err(error);
  return $ok({ result, newSecretKey });
}

export async function $encryptObj(
  cryptoType: CryptoType,
  obj: Record<string, unknown> | null,
  key: string | WebApiCryptoKey | NodeCryptoKey,
): Promise<Result<{ encrypted: string; newSecretKey: WebApiCryptoKey | undefined }>> {
  const { result, error } = $stringifyObj(obj);
  if (error) return $err(error);
  return await $encrypt(cryptoType, result, key);
}

export async function $decryptObj(
  cryptoType: CryptoType,
  encrypted: string | null,
  key: string | WebApiCryptoKey | NodeCryptoKey,
): Promise<Result<{ result: Record<string, unknown>; newSecretKey: WebApiCryptoKey | undefined }>> {
  const { result, newSecretKey, error } = await $decrypt(cryptoType, encrypted, key);
  if (error) return $err(error);
  const { result: parsedObj, error: parseError } = $parseToObj(result);
  if (parseError) return $err(parseError);
  return $ok({ result: parsedObj, newSecretKey });
}
