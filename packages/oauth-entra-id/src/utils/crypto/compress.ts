import { Buffer } from 'node:buffer';
import pako from 'pako';
import { $err, $ok, type Result } from '~/error';
import { FORMAT } from './encrypt';
import { $parseToObj, $stringifyObj } from './objects';

export function $compress(str: string | null | undefined): Result<string> {
  if (!str || str.trim().length === 0) {
    return $err('nullish_value', { error: 'Invalid data', description: 'Empty data to compress' });
  }

  try {
    const compressed = pako.deflate(str, { level: 6, windowBits: 15, memLevel: 7, strategy: 0, raw: false });
    return $ok(`${Buffer.from(compressed).toString(FORMAT)}..`);
  } catch (error) {
    return $err('crypto_error', {
      error: 'Failed to compress data',
      description: error instanceof Error ? error.message : String(error),
    });
  }
}

export function $decompress(str: string | null | undefined): Result<string> {
  if (!str || str.trim().length === 0) {
    return $err('nullish_value', { error: 'Invalid data', description: 'Empty data to decompress' });
  }
  if (!str.endsWith('..')) {
    return $err('invalid_format', { error: 'Invalid compressed data', description: 'String does not end with ".."' });
  }

  try {
    const compressedBuffer = Buffer.from(str.slice(0, -2), FORMAT);
    return $ok(pako.inflate(compressedBuffer, { to: 'string' }));
  } catch (error) {
    return $err('crypto_error', {
      error: 'Failed to decompress data',
      description: error instanceof Error ? error.message : String(error),
    });
  }
}

export function $compressObj(
  obj: Record<string, unknown> | null | undefined,
  disableCompression = false,
): Result<{ result: string; wasCompressed: boolean }> {
  const { result, error } = $stringifyObj(obj);
  if (error) return $err(error);

  if (disableCompression) return $ok({ result, wasCompressed: false });
  const { result: compressed, error: compressError } = $compress(result);
  if (compressError) return $ok({ result, wasCompressed: false });

  const wasCompressed = compressed.length < result.length;
  return $ok({ result: wasCompressed ? compressed : result, wasCompressed });
}

export function $decompressObj(
  str: string | null | undefined,
): Result<{ result: Record<string, unknown>; wasCompressed: boolean }> {
  if (str && !str.endsWith('..')) {
    const { result: parsedObj, error: parseError } = $parseToObj(str);
    if (parseError) return $err(parseError);
    return $ok({ result: parsedObj, wasCompressed: false });
  }

  const { result, error } = $decompress(str);
  if (error) return $err(error);
  const { result: parsedObj, error: parseError } = $parseToObj(result);
  if (parseError) return $err(parseError);
  return $ok({ result: parsedObj, wasCompressed: true });
}
