import {
  isNodeKey,
  isWebApiKey,
  type NodeKey,
  nodeKit,
  parseToObj,
  stringifyObj,
  type WebApiKey,
  webApiKit,
} from 'cipher-kit';
import { $err, $ok } from '~/error';
import type { Result } from '~/exports';
import type { CryptoType } from '~/types';
import { $isStr } from './zod';

export function $generateUuid(cryptoType: CryptoType): Result<{ uuid: string }> {
  const uuid = cryptoType === 'node' ? nodeKit.generateUuid() : webApiKit.generateUuid();
  if (uuid.error)
    return $err({
      msg: 'Failed to generate UUID',
      desc: `UUID generation error: message: ${uuid.error.message}, description: ${uuid.error.description}`,
    });
  return $ok({ uuid: uuid.result });
}

export function $createSecretKey(cryptoType: CryptoType, key: string): Result<{ newSecretKey: string | NodeKey }> {
  if (cryptoType === 'web-api') return $ok({ newSecretKey: key });

  const { secretKey, error } = nodeKit.createSecretKey(key);
  if (error)
    return $err({
      msg: 'Failed to create secret key',
      desc: `Secret key creation error: message: ${error.message}, description: ${error.description}`,
    });
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

  const { secretKey: atKey, error: atError } = nodeKit.createSecretKey(keys.accessToken);
  if (atError) {
    return $err({
      msg: 'Failed to create access token key',
      desc: `Key creation error: message: ${atError.message}, description: ${atError.description}`,
    });
  }

  const { secretKey: rtKey, error: rtError } = nodeKit.createSecretKey(keys.refreshToken);
  if (rtError) {
    return $err({
      msg: 'Failed to create refresh token key',
      desc: `Key creation error: message: ${rtError.message}, description: ${rtError.description}`,
    });
  }

  const { secretKey: stateKey, error: stateError } = nodeKit.createSecretKey(keys.state);
  if (stateError) {
    return $err({
      msg: 'Failed to create state key',
      desc: `Key creation error: message: ${stateError.message}, description: ${stateError.description}`,
    });
  }

  const { secretKey: ticketKey, error: ticketError } = nodeKit.createSecretKey(keys.ticket);
  if (ticketError) {
    return $err({
      msg: 'Failed to create ticket key',
      desc: `Key creation error: message: ${ticketError.message}, description: ${ticketError.description}`,
    });
  }

  return $ok({ secretKeys: { accessToken: atKey, refreshToken: rtKey, state: stateKey, ticket: ticketKey } });
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
    const { secretKey, error: secretKeyError } = nodeKit.createSecretKey(key);
    if (secretKeyError) {
      return $err({
        msg: 'Failed to create Node secret key',
        desc: `Secret key creation error: message: ${secretKeyError.message}, description: ${secretKeyError.description}`,
      });
    }

    const encrypted = nodeKit.encrypt(data, secretKey);
    if (encrypted.error) {
      return $err({
        msg: 'Encryption failed',
        desc: `Encryption error: message: ${encrypted.error.message}, description: ${encrypted.error.description}`,
      });
    }
    return $ok({ encrypted: encrypted.result, newSecretKey: undefined });
  }

  if (!$isStr(key) && !isWebApiKey(key)) {
    return $err({ msg: 'Invalid key type', desc: 'Expected string or WebApiKey' });
  }

  const { secretKey, error: secretKeyError } = await webApiKit.createSecretKey(key);
  if (secretKeyError) {
    return $err({
      msg: 'Failed to create Web API secret key',
      desc: `Secret key creation error: message: ${secretKeyError.message}, description: ${secretKeyError.description}`,
    });
  }
  const encrypted = await webApiKit.encrypt(data, secretKey);
  if (encrypted.error) {
    return $err({
      msg: 'Encryption failed',
      desc: `Encryption error: message: ${encrypted.error.message}, description: ${encrypted.error.description}`,
    });
  }
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

    const { secretKey, error: secretKeyError } = nodeKit.createSecretKey(key);
    if (secretKeyError) {
      return $err({
        msg: 'Failed to create Node secret key',
        desc: `Secret key creation error: message: ${secretKeyError.message}, description: ${secretKeyError.description}`,
      });
    }

    const decrypted = nodeKit.decrypt(encrypted, secretKey);
    if (decrypted.error) {
      return $err({
        msg: 'Decryption failed',
        desc: `Decryption error: message: ${decrypted.error.message}, description: ${decrypted.error.description}`,
      });
    }
    return $ok({ result: decrypted.result, newSecretKey: undefined });
  }
  if (!$isStr(key) && !isWebApiKey(key)) {
    return $err({ msg: 'Invalid key type', desc: 'Expected string or WebApiKey' });
  }

  const { secretKey, error: secretKeyError } = await webApiKit.createSecretKey(key);
  if (secretKeyError) {
    return $err({
      msg: 'Failed to create Web API secret key',
      desc: `Secret key creation error: message: ${secretKeyError.message}, description: ${secretKeyError.description}`,
    });
  }
  const decrypted = await webApiKit.decrypt(encrypted, secretKey);
  if (decrypted.error) {
    return $err({
      msg: 'Decryption failed',
      desc: `Decryption error: message: ${decrypted.error.message}, description: ${decrypted.error.description}`,
    });
  }
  return $ok({ result: decrypted.result, newSecretKey: secretKey });
}

export async function $encryptObj(
  cryptoType: CryptoType,
  obj: Record<string, unknown> | null,
  key: string | WebApiKey | NodeKey,
): Promise<Result<{ encrypted: string; newSecretKey: WebApiKey | undefined }>> {
  if (!obj) return $err({ msg: 'Invalid data', desc: 'Empty object to encrypt' });
  const { result, error } = stringifyObj(obj);
  if (error)
    return $err({
      msg: 'Failed to stringify object',
      desc: `Stringify error: message: ${error.message}, description: ${error.description}`,
    });
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
  if (error)
    return $err({
      msg: 'Failed to parse object',
      desc: `Parse error: message: ${error.message}, description: ${error.description}`,
    });
  return $ok({ result, newSecretKey: decrypted.newSecretKey });
}
