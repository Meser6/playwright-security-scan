import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import type { PlaywrightTestConfig } from '@playwright/test';
import { ConfigError, withSecurity } from '../../../src/entries/config.ts';
import { getRegistered, resetRegistryForTests } from '../../../src/registry/index.ts';

const ENV = [
  'PW_SEC_MODE',
  'PW_SEC_CONFIG',
  'PW_SEC_RUN_ID',
  'PW_SEC_RUN_SALT',
  'TEST_WORKER_INDEX',
  'CI',
];
let saved: Record<string, string | undefined>;

beforeEach(() => {
  saved = Object.fromEntries(ENV.map((k) => [k, process.env[k]]));
  for (const k of ENV) Reflect.deleteProperty(process.env, k);
  resetRegistryForTests();
});
afterEach(() => {
  for (const k of ENV) {
    if (saved[k] === undefined) Reflect.deleteProperty(process.env, k);
    else process.env[k] = saved[k];
  }
  resetRegistryForTests();
});

const base: PlaywrightTestConfig = {
  workers: 3,
  retries: 2,
  timeout: 10_000,
  reporter: [['html', { open: 'never' }]],
  use: { baseURL: 'https://shop.example.com/app/' },
  projects: [
    { name: 'setup', testMatch: /setup/ },
    { name: 'chromium', use: { baseURL: 'https://api.example.com' } },
  ],
};

describe('withSecurity() (01, chapter 7; 04)', () => {
  test('01-REQ-08 without PW_SEC_MODE the config is returned unchanged (P-02)', () => {
    expect(withSecurity(base)).toBe(base);
    expect(getRegistered()).toBeUndefined();
  });

  test('04-AC-01 PW_SEC_MODE=active fails before tests start', () => {
    process.env.PW_SEC_MODE = 'active';
    expect(() => withSecurity(base)).toThrow(ConfigError);
    expect(() => withSecurity(base)).toThrow(/MODE|not available/);
  });

  test('04-REQ-01 unknown modes list the values; values are case-insensitive', () => {
    process.env.PW_SEC_MODE = 'scna';
    expect(() => withSecurity(base)).toThrow(/Allowed values: scan, baseline/);
    process.env.PW_SEC_MODE = 'SCAN';
    expect(() => withSecurity(base)).not.toThrow();
    expect(getRegistered()?.mode).toBe('scan');
  });

  test('01-REQ-07 appends the reporter and keeps everything else (D-04)', () => {
    process.env.PW_SEC_MODE = 'baseline';
    const out = withSecurity(base);
    expect(out).not.toBe(base);
    expect(out.workers).toBe(3);
    expect(out.retries).toBe(2);
    expect(out.timeout).toBe(10_000);
    const reporters = out.reporter as unknown as [string, unknown?][];
    expect(reporters[0]).toEqual(['html', { open: 'never' }]);
    expect(reporters[1]?.[0]).toMatch(/reporter(\.ts|\.js|\.cjs)?$/);
    expect(withSecurity({} as PlaywrightTestConfig).reporter).toEqual([
      ['list'],
      [expect.stringMatching(/reporter/)],
    ]);
  });

  test('01-REQ-05 registers the config, scanned projects and baseURL origins', () => {
    process.env.PW_SEC_MODE = 'scan';
    withSecurity(base, { scope: { projects: ['chromium'] } });
    const state = getRegistered();
    expect(state?.scannedProjects).toEqual(['chromium']);
    expect(state?.baseOrigins).toEqual(['https://api.example.com']);
    expect(state?.configPassed).toBe(true);
    expect(state?.runId).not.toBe('');
    expect(state?.salt).toMatch(/^[0-9a-f]{32}$/);
    expect(process.env.PW_SEC_RUN_SALT).toBe(state?.salt);
  });

  test('03-REQ-02 an invalid package config throws with every problem', () => {
    process.env.PW_SEC_MODE = 'scan';
    let error: unknown;
    try {
      withSecurity(base, {
        rules: { 'cookie.no-htponly': 'off' },
        gate: { minSeverity: 'x' as never },
      });
    } catch (e) {
      error = e;
    }
    expect(error).toBeInstanceOf(ConfigError);
    expect((error as ConfigError).issues.map((i) => i.code)).toEqual([
      'CONFIG_UNKNOWN_RULE',
      'CONFIG_INVALID_VALUE',
    ]);
    expect((error as Error).message).toContain('Did you mean "cookie.no-httponly"?');
  });

  test('a config without baseURL and scope.origins registers SCOPE_EMPTY', () => {
    process.env.PW_SEC_MODE = 'scan';
    withSecurity({});
    expect(getRegistered()?.warnings.map((w) => w.code)).toEqual(['SCOPE_EMPTY']);
    expect(getRegistered()?.warnings[0]?.message).toContain('set `use.baseURL` or `scope.origins`');
  });

  test('a localhost baseURL makes transport rules advisory (05-REQ-06)', () => {
    process.env.PW_SEC_MODE = 'scan';
    withSecurity({ use: { baseURL: 'http://localhost:3000' } });
    expect(getRegistered()?.warnings.map((w) => w.code)).toEqual(['LOCAL_ORIGIN']);
  });

  test('03-REQ-04 PW_SEC_CONFIG wins over the second argument', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pw-sec-'));
    const file = join(dir, 'pw-sec.config.json');
    writeFileSync(file, JSON.stringify({ gate: { minSeverity: 'high' } }));
    process.env.PW_SEC_MODE = 'scan';
    process.env.PW_SEC_CONFIG = file;
    withSecurity(base, { gate: { minSeverity: 'low' } });
    expect(getRegistered()?.config.gate.minSeverity).toBe('high');
    process.env.PW_SEC_CONFIG = join(dir, 'missing.json');
    expect(() => withSecurity(base)).toThrow(/CONFIG|cannot load/);
  });
});
