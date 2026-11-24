import { describe, expect, test } from 'vitest';
import { VERSION } from '../../src/version.ts';
import packageJson from '../../package.json' with { type: 'json' };

describe('version', () => {
  test('matches package.json', () => {
    expect(VERSION).toBe(packageJson.version);
  });
});
