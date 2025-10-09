import { tryParseToObj, tryStringifyObj } from 'cipher-kit';
import {
  tryCreateSecretKey as createNodeSecretKey,
  isNodeSecretKey,
  type NodeSecretKey,
  tryDecrypt as nodeDecrypt,
  tryEncrypt as nodeEncrypt,
  tryGenerateUuid as nodeGenerateUuid,
} from 'cipher-kit/node';
import {
  tryCreateSecretKey as createWebSecretKey,
  isWebSecretKey,
  type WebSecretKey,
  tryDecrypt as webDecrypt,
  tryEncrypt as webEncrypt,
  tryGenerateUuid as webGenerateUuid,
} from 'cipher-kit/web-api';
import { $err, $ok, $stringErr } from '~/error';
import type { Result } from '~/exports';
import type { CryptoType } from '~/types';
import { $isStr } from './zod';

export function $generateUuid(cryptoType: CryptoType): Result<{ uuid: string }> {
  const uuid = cryptoType === 'node' ? nodeGenerateUuid() : webGenerateUuid();
  if (uuid.error) return $err({ msg: 'Failed to generate UUID', desc: $stringErr(uuid.error) });
  return $ok({ uuid: uuid.result });
}

export function $createSecretKey(
  cryptoType: CryptoType,
  key: string,
): Result<{ newSecretKey: string | NodeSecretKey }> {
  if (cryptoType === 'web-api') return $ok({ newSecretKey: key });

  const secretKey = createNodeSecretKey(key);
  if (secretKey.error) return $err({ msg: 'Failed to create Node secret key', desc: $stringErr(secretKey.error) });
  return $ok({ newSecretKey: secretKey.result });
}

export function $newSecretKeys(
  cryptoType: CryptoType,
  keys: { accessToken: string; refreshToken: string; state: string; ticket: string },
): Result<{
  secretKeys: {
    accessToken: string | NodeSecretKey;
    refreshToken: string | NodeSecretKey;
    state: string | NodeSecretKey;
    ticket: string | NodeSecretKey;
  };
}> {
  if (cryptoType === 'web-api') {
    return $ok({ secretKeys: keys });
  }

  const secretKeys = {} as Record<keyof typeof keys, NodeSecretKey>;
  for (const name of Object.keys(keys) as (keyof typeof keys)[]) {
    const secretKey = createNodeSecretKey(keys[name]);
    if (secretKey.error)
      return $err({ msg: `Failed to create ${name} key`, desc: `Key Creation - ${$stringErr(secretKey.error)}` });
    secretKeys[name] = secretKey.result;
  }

  return $ok({ secretKeys: secretKeys });
}

export async function $encrypt(
  cryptoType: CryptoType,
  data: string | null,
  key: string | WebSecretKey | NodeSecretKey,
): Promise<Result<{ encrypted: string; newWebSecretKey: WebSecretKey | undefined }>> {
  if (!data) return $err({ msg: 'Invalid data', desc: 'Empty string to encrypt' });
  if (cryptoType === 'node') {
    if ($isStr(key)) {
      const secretKey = createNodeSecretKey(key);
      if (secretKey.error) {
        return $err({ msg: 'Failed to create Node secret key', desc: `Key Creation - ${$stringErr(secretKey.error)}` });
      }

      const encrypted = nodeEncrypt(data, secretKey.result);
      if (encrypted.error) {
        return $err({ msg: 'Encryption failed', desc: `Encryption - ${$stringErr(encrypted.error)}` });
      }

      return $ok({ encrypted: encrypted.result, newWebSecretKey: undefined });
    }

    if (!isNodeSecretKey(key)) {
      return $err({ msg: 'Invalid key type', desc: 'Expected NodeSecretKey or string' });
    }

    const encrypted = nodeEncrypt(data, key);
    if (encrypted.error) return $err({ msg: 'Encryption failed', desc: `Encryption - ${$stringErr(encrypted.error)}` });

    return $ok({ encrypted: encrypted.result, newWebSecretKey: undefined });
  }

  if ($isStr(key)) {
    const secretKey = await createWebSecretKey(key);
    if (secretKey.error) {
      return $err({ msg: 'Failed to create Web API secret key', desc: $stringErr(secretKey.error) });
    }

    const encrypted = await webEncrypt(data, secretKey.result);
    if (encrypted.error) {
      return $err({ msg: 'Encryption failed', desc: `Encryption - ${$stringErr(encrypted.error)}` });
    }

    return $ok({ encrypted: encrypted.result, newWebSecretKey: secretKey.result });
  }

  if (!isWebSecretKey(key)) {
    return $err({ msg: 'Invalid key type', desc: 'Expected WebSecretKey or string' });
  }

  const encrypted = await webEncrypt(data, key);
  if (encrypted.error) return $err({ msg: 'Encryption failed', desc: `Encryption - ${$stringErr(encrypted.error)}` });

  return $ok({ encrypted: encrypted.result, newWebSecretKey: key });
}

export async function $decrypt(
  cryptoType: CryptoType,
  encrypted: string | null,
  key: string | WebSecretKey | NodeSecretKey,
): Promise<Result<{ result: string; newWebSecretKey: WebSecretKey | undefined }>> {
  if (!encrypted) return $err({ msg: 'Invalid data', desc: 'Empty string to decrypt' });
  if (cryptoType === 'node') {
    if ($isStr(key)) {
      const secretKey = createNodeSecretKey(key);
      if (secretKey.error) {
        return $err({ msg: 'Failed to create Node secret key', desc: `Key Creation - ${$stringErr(secretKey.error)}` });
      }

      const decrypted = nodeDecrypt(encrypted, secretKey.result);
      if (decrypted.error) {
        return $err({ msg: 'Decryption failed', desc: `Decryption - ${$stringErr(decrypted.error)}` });
      }

      return $ok({ result: decrypted.result, newWebSecretKey: undefined });
    }

    if (!isNodeSecretKey(key)) {
      return $err({ msg: 'Invalid key type', desc: 'Expected NodeSecretKey or string' });
    }

    const decrypted = nodeDecrypt(encrypted, key);
    if (decrypted.error) return $err({ msg: 'Decryption failed', desc: `Decryption - ${$stringErr(decrypted.error)}` });

    return $ok({ result: decrypted.result, newWebSecretKey: undefined });
  }
  if ($isStr(key)) {
    const secretKey = await createWebSecretKey(key);
    if (secretKey.error) {
      return $err({ msg: 'Failed to create Web API secret key', desc: $stringErr(secretKey.error) });
    }

    const decrypted = await webDecrypt(encrypted, secretKey.result);
    if (decrypted.error) {
      return $err({ msg: 'Decryption failed', desc: `Decryption - ${$stringErr(decrypted.error)}` });
    }

    return $ok({ result: decrypted.result, newWebSecretKey: secretKey.result });
  }

  if (!isWebSecretKey(key)) {
    return $err({ msg: 'Invalid key type', desc: 'Expected WebSecretKey or string' });
  }

  const decrypted = await webDecrypt(encrypted, key);
  if (decrypted.error) return $err({ msg: 'Decryption failed', desc: `Decryption - ${$stringErr(decrypted.error)}` });

  return $ok({ result: decrypted.result, newWebSecretKey: key });
}

export async function $encryptObj(
  cryptoType: CryptoType,
  obj: Record<string, unknown> | null,
  key: string | WebSecretKey | NodeSecretKey,
): Promise<Result<{ encrypted: string; newWebSecretKey: WebSecretKey | undefined }>> {
  if (!obj) return $err({ msg: 'Invalid data', desc: 'Empty object to encrypt' });
  const { result, error } = tryStringifyObj(obj);
  if (error) return $err({ msg: 'Failed to stringify object', desc: $stringErr(error) });
  return await $encrypt(cryptoType, result, key);
}

export async function $decryptObj(
  cryptoType: CryptoType,
  encrypted: string | null,
  key: string | WebSecretKey | NodeSecretKey,
): Promise<Result<{ result: Record<string, unknown>; newWebSecretKey: WebSecretKey | undefined }>> {
  if (!encrypted) return $err({ msg: 'Invalid data', desc: 'Empty string to decrypt' });
  const decrypted = await $decrypt(cryptoType, encrypted, key);
  if (decrypted.error) return decrypted;
  const { result, error } = tryParseToObj(decrypted.result);
  if (error) return $err({ msg: 'Failed to parse object', desc: $stringErr(error) });
  return $ok({ result, newWebSecretKey: decrypted.newWebSecretKey });
}
