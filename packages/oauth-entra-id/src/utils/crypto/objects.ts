import { $err, $ok, type Result } from '~/error';
import { $isPlainObject, $isString } from '../zod';

export function $stringifyObj(obj: Record<string, unknown> | null | undefined): Result<string> {
  if (!obj) return $err('nullish_value', { error: 'Invalid data' });

  try {
    if (!$isPlainObject(obj)) {
      return $err('invalid_format', { error: 'Invalid object format', description: 'Input is not a plain object' });
    }

    const str = JSON.stringify(obj);
    if (!$isString(str)) {
      return $err('invalid_format', {
        error: 'Stringify failed',
        description: 'Empty string result from JSON.stringify',
      });
    }

    return $ok(str);
  } catch (error) {
    return $err('invalid_format', {
      error: 'Stringify failed',
      description: `Failed to stringify object, input: ${JSON.stringify(obj)}, error: ${error instanceof Error ? error.message : String(error)}`,
    });
  }
}

export function $parseToObj(str: string | null | undefined): Result<{ result: Record<string, unknown> }> {
  if (!$isString(str)) {
    return $err('nullish_value', { error: 'Invalid data', description: 'Empty string to parse' });
  }

  try {
    const obj = JSON.parse(str);
    if (!$isPlainObject(obj)) {
      return $err('invalid_format', {
        error: 'Invalid object format',
        description: 'Parsed data is not a plain object',
      });
    }

    if (!obj) {
      return $err('invalid_format', {
        error: 'Invalid object format',
        description: 'Parsed data is null or undefined',
      });
    }
    return $ok({ result: obj });
  } catch (error) {
    return $err('invalid_format', {
      error: 'Parse failed',
      description: `Failed to parse JSON, input: ${str}, error: ${error instanceof Error ? error.message : String(error)}`,
    });
  }
}
