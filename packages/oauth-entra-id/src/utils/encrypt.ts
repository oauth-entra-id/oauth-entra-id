import { parseToObj, stringifyObj } from 'cipher-kit';
import {
  createSecretKey as createNodeKey,
  isNodeKey,
  type NodeKey,
  decrypt as nodeDecrypt,
  encrypt as nodeEncrypt,
  generateUuid as nodeGenerateUuid,
} from 'cipher-kit/node';
import {
  createSecretKey as createWebApiKey,
  isWebApiKey,
  type WebApiKey,
  decrypt as webApiDecrypt,
  encrypt as webApiEncrypt,
  generateUuid as webApiGenerateUuid,
} from 'cipher-kit/web-api';
import { $err, $ok, $stringErr } from '~/error';
import type { Result } from '~/exports';
import type { CryptoType } from '~/types';
import { $isStr } from './zod';

export function $generateUuid(cryptoType: CryptoType): Result<{ uuid: string }> {
  const uuid = cryptoType === 'node' ? nodeGenerateUuid() : webApiGenerateUuid();
  if (uuid.error) return $err({ msg: 'Failed to generate UUID', desc: $stringErr(uuid.error) });
  return $ok({ uuid: uuid.result });
}

export function $createSecretKey(cryptoType: CryptoType, key: string): Result<{ newSecretKey: string | NodeKey }> {
  if (cryptoType === 'web-api') return $ok({ newSecretKey: key });

  const { secretKey, error } = createNodeKey(key);
  if (error) return $err({ msg: 'Failed to create Node secret key', desc: $stringErr(error) });
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

  const secretKeys = {} as Record<keyof typeof keys, NodeKey>;
  for (const name of Object.keys(keys) as (keyof typeof keys)[]) {
    const { secretKey, error } = createNodeKey(keys[name]);
    if (error) return $err({ msg: `Failed to create ${name} key`, desc: `Key Creation - ${$stringErr(error)}` });
    secretKeys[name] = secretKey;
  }

  return $ok({ secretKeys: secretKeys });
}

export async function $encrypt(
  cryptoType: CryptoType,
  data: string | null,
  key: string | WebApiKey | NodeKey,
): Promise<Result<{ encrypted: string; newSecretKey: WebApiKey | undefined }>> {
  if (!data) return $err({ msg: 'Invalid data', desc: 'Empty string to encrypt' });
  if (cryptoType === 'node') {
    if (!$isStr(key) && !isNodeKey(key)) {
      return $err({ msg: 'Invalid key type', desc: 'Expected NodeKey or string' });
    }
    const { secretKey, error: secretKeyError } = createNodeKey(key);
    if (secretKeyError) {
      return $err({ msg: 'Failed to create Node secret key', desc: `Key Creation - ${$stringErr(secretKeyError)}` });
    }

    const encrypted = nodeEncrypt(data, secretKey);
    if (encrypted.error) return $err({ msg: 'Encryption failed', desc: `Encryption - ${$stringErr(encrypted.error)}` });

    return $ok({ encrypted: encrypted.result, newSecretKey: undefined });
  }

  if (!$isStr(key) && !isWebApiKey(key)) {
    return $err({ msg: 'Invalid key type', desc: 'Expected string or WebApiKey' });
  }

  const { secretKey, error: secretKeyError } = await createWebApiKey(key);
  if (secretKeyError) return $err({ msg: 'Failed to create Web API secret key', desc: $stringErr(secretKeyError) });

  const encrypted = await webApiEncrypt(data, secretKey);
  if (encrypted.error) return $err({ msg: 'Encryption failed', desc: `Encryption - ${$stringErr(encrypted.error)}` });

  return $ok({ encrypted: encrypted.result, newSecretKey: secretKey });
}

export async function $decrypt(
  cryptoType: CryptoType,
  encrypted: string | null,
  key: string | WebApiKey | NodeKey,
): Promise<Result<{ result: string; newSecretKey: WebApiKey | undefined }>> {
  if (!encrypted) return $err({ msg: 'Invalid data', desc: 'Empty string to decrypt' });
  if (cryptoType === 'node') {
    if (!$isStr(key) && !isNodeKey(key)) {
      return $err({ msg: 'Invalid key type', desc: 'Expected NodeKey or string' });
    }

    const { secretKey, error: secretKeyError } = createNodeKey(key);
    if (secretKeyError) return $err({ msg: 'Failed to create Node secret key', desc: $stringErr(secretKeyError) });

    const decrypted = nodeDecrypt(encrypted, secretKey);
    if (decrypted.error) return $err({ msg: 'Decryption failed', desc: `Decryption - ${$stringErr(decrypted.error)}` });

    return $ok({ result: decrypted.result, newSecretKey: undefined });
  }
  if (!$isStr(key) && !isWebApiKey(key)) {
    return $err({ msg: 'Invalid key type', desc: 'Expected string or WebApiKey' });
  }

  const { secretKey, error: secretKeyError } = await createWebApiKey(key);
  if (secretKeyError) return $err({ msg: 'Failed to create Web API secret key', desc: $stringErr(secretKeyError) });

  const decrypted = await webApiDecrypt(encrypted, secretKey);
  if (decrypted.error) return $err({ msg: 'Decryption failed', desc: `Decryption - ${$stringErr(decrypted.error)}` });

  return $ok({ result: decrypted.result, newSecretKey: secretKey });
}

export async function $encryptObj(
  cryptoType: CryptoType,
  obj: Record<string, unknown> | null,
  key: string | WebApiKey | NodeKey,
): Promise<Result<{ encrypted: string; newSecretKey: WebApiKey | undefined }>> {
  if (!obj) return $err({ msg: 'Invalid data', desc: 'Empty object to encrypt' });
  const { result, error } = stringifyObj(obj);
  if (error) return $err({ msg: 'Failed to stringify object', desc: $stringErr(error) });
  return await $encrypt(cryptoType, result, key);
}

export async function $decryptObj(
  cryptoType: CryptoType,
  encrypted: string | null,
  key: string | WebApiKey | NodeKey,
): Promise<Result<{ result: Record<string, unknown>; newSecretKey: WebApiKey | undefined }>> {
  if (!encrypted) return $err({ msg: 'Invalid data', desc: 'Empty string to decrypt' });
  const decrypted = await $decrypt(cryptoType, encrypted, key);
  if (decrypted.error) return decrypted;
  const { result, error } = parseToObj(decrypted.result);
  if (error) return $err({ msg: 'Failed to parse object', desc: $stringErr(error) });
  return $ok({ result, newSecretKey: decrypted.newSecretKey });
}
