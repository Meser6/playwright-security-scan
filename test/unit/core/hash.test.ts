import { createHash, randomBytes } from 'node:crypto';
import { describe, expect, test } from 'vitest';
import { sha256, sha256Bytes } from '../../../src/core/hash/index.ts';

describe('pure SHA-256 (core cannot use node:crypto)', () => {
  test('known vectors', () => {
    expect(sha256('')).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    expect(sha256('abc')).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    expect(sha256('zażółć gęślą jaźń')).toBe(
      createHash('sha256').update('zażółć gęślą jaźń', 'utf8').digest('hex'),
    );
  });

  test('matches node:crypto for lengths around the block boundaries', () => {
    for (const length of [1, 55, 56, 63, 64, 65, 119, 120, 1000, 100_000]) {
      const bytes = new Uint8Array(randomBytes(length));
      expect(sha256Bytes(bytes)).toBe(createHash('sha256').update(bytes).digest('hex'));
    }
  });
});
