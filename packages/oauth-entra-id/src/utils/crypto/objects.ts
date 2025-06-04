import { $err, $ok, type Result } from '~/error';

export function $isPlainObject(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === 'object' &&
    value !== null &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null)
  );
}

export function $stringifyObj(obj: Record<string, unknown> | null | undefined): Result<string> {
  if (!obj) return $err('nullish_value', { error: 'Invalid data' });

  try {
    if (!$isPlainObject(obj)) {
      return $err('invalid_format', { error: 'Invalid object format', description: 'Input is not a plain object' });
    }

    const str = JSON.stringify(obj);
    if (!str || str.trim().length === 0) {
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
  if (!str || str.trim().length === 0) {
    return $err('nullish_value', { error: 'Invalid data', description: 'Empty string' });
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
