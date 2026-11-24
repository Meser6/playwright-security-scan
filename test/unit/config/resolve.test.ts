import { describe, expect, test } from 'vitest';
import { enabledRuleCount, resolveConfig } from '../../../src/core/config/index.ts';
import type { ResolvedSecurityConfig } from '../../../src/core/config/index.ts';
import { RULE_MANIFEST } from '../../../src/core/manifest/rules.ts';

function resolved(input?: Parameters<typeof resolveConfig>[0]): ResolvedSecurityConfig {
  const result = resolveConfig(input);
  if (!result.ok) throw new Error(JSON.stringify(result.issues));
  return result.config;
}

describe('config resolution (03, chapter 4; 06, chapter 3)', () => {
  test('defaults (P-13)', () => {
    const c = resolved();
    expect(c.gate).toEqual({
      minSeverity: 'medium',
      minConfidence: 'medium',
      failOnExpired: true,
      failOnNoTraffic: true,
    });
    expect(c.limits.maxBodyBytes).toBe(1_048_576);
    expect(c.baseline.path).toBe('security-baseline.json');
    expect(c.report.junitPath).toBe('reports/pw-sec/junit.xml');
    expect(c.preset).toBe('recommended');
    expect(c.scope.projects).toBe('all');
  });

  test('recommended enables the 44 MVP rules; strict adds the 2 strict-only rules', () => {
    expect(RULE_MANIFEST).toHaveLength(46);
    expect(enabledRuleCount(resolved())).toBe(44);
    expect(enabledRuleCount(resolved({ rules: { preset: 'strict' } }))).toBe(46);
  });

  test('strict raises info to low and low/high to medium; minimal keeps high-confidence rules', () => {
    const strict = resolved({ rules: { preset: 'strict' } }).rules;
    expect(strict['cookie.samesite-missing']?.severity).toBe('low');
    expect(strict['header.hsts-missing']?.severity).toBe('medium');
    expect(strict['cookie.samesite-none']?.severity).toBe('low');
    const minimal = resolved({ rules: { preset: 'minimal' } }).rules;
    expect(minimal['header.clickjacking']?.enabled).toBe(false);
    expect(minimal['header.csp-missing']?.enabled).toBe(true);
  });

  test('per-rule settings: off, on, severity and merged options', () => {
    const rules = resolved({
      rules: {
        'header.csp-missing': 'off',
        'header.coop-missing': 'on',
        'data.jwt-long-lived': { severity: 'medium', options: { maxJwtHours: 48 } },
      },
    }).rules;
    expect(rules['header.csp-missing']?.enabled).toBe(false);
    expect(rules['header.coop-missing']?.enabled).toBe(true);
    expect(rules['data.jwt-long-lived']).toEqual({
      enabled: true,
      severity: 'medium',
      confidence: 'high',
      options: { maxJwtHours: 48 },
    });
  });

  test('report.junitPath follows report.dir unless set', () => {
    expect(resolved({ report: { dir: 'out/sec/' } }).report.junitPath).toBe('out/sec/junit.xml');
    expect(resolved({ report: { dir: 'x', junitPath: 'junit/sec.xml' } }).report.junitPath).toBe(
      'junit/sec.xml',
    );
  });
});
