import { describe, expect, test } from 'vitest';
import { $compressObj, $decompressObj } from '~/utils/crypto/compress';

describe('Compress Small Object', () => {
  const smallObj = { a: 'test', b: 123, c: true };
  const compressedObjRes = $compressObj(smallObj);
  const decompressedObjRes = $decompressObj(compressedObjRes.result);

  test('Compress Function', () => {
    expect(compressedObjRes.success).toEqual(true);
    expect(compressedObjRes.result).toBeDefined();
    expect(compressedObjRes.wasCompressed).toEqual(false);
  });

  test('Decompress Function', () => {
    expect(decompressedObjRes.success).toEqual(true);
    expect(decompressedObjRes.result).toEqual(smallObj);
    expect(decompressedObjRes.wasCompressed).toEqual(false);
  });
});
