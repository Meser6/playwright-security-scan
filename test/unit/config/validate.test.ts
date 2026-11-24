import { describe, expect, test } from 'vitest';
import { resolveConfig, validateConfig } from '../../../src/core/config/index.ts';

const codes = (input: unknown) => validateConfig(input).map((i) => `${i.code} ${i.path}`);

describe('config validation (03-REQ-02)', () => {
  test("03-AC-02 rules: { 'cookie.no-htponly': 'off' } fails with the hint cookie.no-httponly", () => {
    const issues = validateConfig({ rules: { 'cookie.no-htponly': 'off' } });
    expect(issues).toHaveLength(1);
    expect(issues[0]?.code).toBe('CONFIG_UNKNOWN_RULE');
    expect(issues[0]?.message).toBe(
      'rules.cookie.no-htponly: unknown rule id. Did you mean "cookie.no-httponly"?',
    );
    expect(resolveConfig({ rules: { 'cookie.no-htponly': 'off' } }).ok).toBe(false);
  });

  test('unknown options get the closest name and the allowed list', () => {
    const issues = validateConfig({ gate: { minSeverty: 'high' }, scop: {} });
    expect(issues.map((i) => i.message)).toEqual([
      'gate.minSeverty: unknown option. Did you mean "minSeverity"?',
      'scop: unknown option. Did you mean "scope"?',
    ]);
    expect(issues[0]?.hint).toContain('minConfidence');
  });

  test('wrong types and values name the option, the value and the allowed values', () => {
    expect(
      codes({
        gate: { minSeverity: 'severe', failOnExpired: 'yes' },
        limits: { maxBodyBytes: -1 },
        scope: {
          origins: ['example.com', 'https://*.example.com', 'https://ok.example.com'],
          projects: 'some',
        },
        rules: {
          preset: 'paranoid',
          'header.hsts-weak': { options: { minMaxAge: '1y', other: 1 } },
        },
      }),
    ).toEqual([
      'CONFIG_INVALID_VALUE gate.minSeverity',
      'CONFIG_INVALID_TYPE gate.failOnExpired',
      'CONFIG_INVALID_TYPE limits.maxBodyBytes',
      'CONFIG_INVALID_VALUE scope.origins[0]',
      'CONFIG_INVALID_TYPE scope.projects',
      'CONFIG_INVALID_VALUE rules.preset',
      'CONFIG_INVALID_TYPE rules.header.hsts-weak.options.minMaxAge',
      'CONFIG_UNKNOWN_OPTION rules.header.hsts-weak.options.other',
    ]);
  });

  test('rules without options reject options', () => {
    expect(codes({ rules: { 'header.csp-missing': { options: { x: 1 } } } })).toEqual([
      'CONFIG_UNKNOWN_OPTION rules.header.csp-missing.options.x',
    ]);
  });

  test('the spec example config is valid', () => {
    expect(
      validateConfig({
        scope: {
          origins: ['https://api.example.com'],
          exclude: ['https://*.google-analytics.com'],
        },
        rules: {
          'header.referrer-policy-unsafe': 'off',
          'cookie.samesite-missing': { severity: 'info' },
          'data.token-in-url': { options: { paramNames: ['token', 'access_token', 'sig'] } },
        },
        gate: { minSeverity: 'medium', minConfidence: 'medium' },
        normalization: { extraIdPatterns: ['me', /^[A-Z]{2}-\d+$/, { regex: '^x', flags: 'i' }] },
      }),
    ).toEqual([]);
  });

  test('a non-object config is rejected', () => {
    expect(codes(42)).toEqual(['CONFIG_INVALID_TYPE ']);
  });
});
