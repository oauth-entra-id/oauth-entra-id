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

describe('Compress Large Object', () => {
  const largeObj = {
    user: {
      id: 'user_1234567890',
      name: 'John Doe',
      email: 'john.doe@example.com',
      isActive: true,
      preferences: {
        theme: 'dark',
        language: 'en-US',
        notifications: {
          email: true,
          sms: false,
          push: true,
        },
      },
      roles: ['admin', 'editor', 'user'],
      stats: {
        posts: 234,
        comments: 876,
        likes: 4321,
        lastLogin: new Date().toISOString(),
      },
      address: {
        street: '1234 Main St',
        city: 'Metropolis',
        state: 'CA',
        zip: '90210',
        geo: { lat: 34.0522, lng: -118.2437 },
      },
    },
    metadata: {
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      tags: Array.from({ length: 100 }, (_, i) => `tag_${i}`),
      notes: Array.from({ length: 50 }, (_, i) => ({
        id: `note_${i}`,
        title: `Note ${i}`,
        content: `This is the content of note number ${i}`,
        pinned: i % 3 === 0,
      })),
    },
    config: {
      features: {
        featureA: true,
        featureB: false,
        featureC: true,
        experimental: { newUI: false, searchV2: true },
      },
      limits: { maxItems: 1000, timeout: 3000, retries: 5 },
    },
    session: {
      token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
      expiresIn: 3600,
      refreshToken: 'ref_123456789',
    },
    logs: Array.from({ length: 200 }, (_, i) => ({
      timestamp: new Date(Date.now() - i * 1000).toISOString(),
      message: `Log message number ${i}`,
      level: ['info', 'warn', 'error'][i % 3],
    })),
  };

  const compressedObjRes = $compressObj(largeObj);
  const decompressedObjRes = $decompressObj(compressedObjRes.result);

  test('Compress Function', () => {
    expect(compressedObjRes.success).toEqual(true);
    expect(compressedObjRes.result).toBeDefined();
    expect(compressedObjRes.wasCompressed).toEqual(true);
  });

  test('Decompress Function', () => {
    expect(decompressedObjRes.success).toEqual(true);
    expect(decompressedObjRes.result).toEqual(largeObj);
    expect(decompressedObjRes.wasCompressed).toEqual(true);
  });
});
