import { Buffer } from 'node:buffer';
import nodeCrypto from 'node:crypto';
import { $err, $ok, type Result } from '~/error';
import { $isPlainObject, $isString } from '../zod';
import { FORMAT, NODE_ALGORITHM } from './encrypt';

export function $generateNodeUuid(): Result<{ uuid: string }> {
  try {
    return $ok({ uuid: nodeCrypto.randomUUID() });
  } catch (error) {
    return $err('crypto_error', {
      error: 'Failed to generate UUID',
      description: error instanceof Error ? error.message : String(error),
      status: 500,
    });
  }
}

export function $createNodeSecretKey(
  key: string | nodeCrypto.KeyObject,
): Result<{ newSecretKey: nodeCrypto.KeyObject }> {
  if (typeof key === 'string') {
    if (!$isString(key)) {
      return $err('nullish_value', { error: 'Invalid secret key', description: 'Empty key for node', status: 500 });
    }

    try {
      const hashedKey = nodeCrypto.createHash('sha256').update(key).digest();
      const newSecretKey = nodeCrypto.createSecretKey(hashedKey);
      return $ok({ newSecretKey: newSecretKey });
    } catch (error) {
      return $err('crypto_error', {
        error: 'Failed to create secret key',
        description: error instanceof Error ? error.message : String(error),
        status: 500,
      });
    }
  }
  if (!$isPlainObject) {
    return $err('misconfiguration', { error: 'Invalid secret key', description: 'Expected a KeyObject' });
  }
  return $ok({ newSecretKey: key });
}

export function $nodeEncrypt(
  data: string,
  secretKey: nodeCrypto.KeyObject,
): Result<{ iv: string; encrypted: string; tag: string }> {
  try {
    const iv = nodeCrypto.randomBytes(12);
    const cipher = nodeCrypto.createCipheriv(NODE_ALGORITHM, secretKey, iv);
    const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();

    return $ok({
      iv: iv.toString(FORMAT),
      encrypted: encrypted.toString(FORMAT),
      tag: tag.toString(FORMAT),
    });
  } catch (error) {
    return $err('crypto_error', {
      error: 'Invalid data',
      description: `Failed to encrypt data: ${data}, ${error instanceof Error ? error.message : String(error)}`,
    });
  }
}

export function $nodeDecrypt(
  iv: string,
  encrypted: string,
  tag: string,
  secretKey: nodeCrypto.KeyObject,
): Result<{ result: string }> {
  try {
    const decipher = nodeCrypto.createDecipheriv(NODE_ALGORITHM, secretKey, Buffer.from(iv, FORMAT));
    decipher.setAuthTag(Buffer.from(tag, FORMAT));

    const decrypted = Buffer.concat([decipher.update(Buffer.from(encrypted, FORMAT)), decipher.final()]);
    return $ok({ result: decrypted.toString('utf8') });
  } catch (error) {
    return $err('crypto_error', {
      error: 'Invalid data',
      description: `Failed to decrypt data: ${encrypted}, ${error instanceof Error ? error.message : String(error)}`,
    });
  }
}
