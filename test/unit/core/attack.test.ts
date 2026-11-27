// The pure part of the attack mode (19): options and checks before the tests, request bodies of
// templates, the mapping of ZAP alerts and the coverage of zap.* baseline entries.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, test } from 'vitest';
import { templateBody } from '../../../src/core/attack/body.ts';
import {
  attackBannerText,
  attackModeIssues,
  attackRole,
  resolveAttack,
} from '../../../src/core/attack/config.ts';
import type { ResolvedAttack } from '../../../src/core/attack/config.ts';
import { confidenceOf, mapAlerts, owaspOf } from '../../../src/core/attack/map.ts';
import type { AttackTemplate, ZapAlert } from '../../../src/core/attack/types.ts';
import { resolveEntries } from '../../../src/core/baseline/index.ts';
import { resolveConfig, validateConfig } from '../../../src/core/config/index.ts';
import { emptyCoverage } from '../../../src/core/coverage.ts';
import { Redactor } from '../../../src/core/fingerprint/index.ts';
import { canonicalOrigin, createKeyBuilder } from '../../../src/core/normalize/index.ts';
import { readMode } from '../../../src/mode/index.ts';
import { EnabledRules, KNOWN_RULE_IDS } from '../../../src/reporter/finish.ts';

const APP = 'https://localhost:4430';
const { alerts } = JSON.parse(
  readFileSync(join(import.meta.dirname, '../../fixtures/zap/alerts.json'), 'utf8'),
) as { alerts: ZapAlert[] };

const attack = (input: Parameters<typeof resolveAttack>[0] = {}): ResolvedAttack =>
  resolveAttack({ allowedOrigins: [APP], ...input });
const ctx = { platform: 'linux', sharded: false, roles: ['customer'] };
const codes = (a: ResolvedAttack, c: Partial<typeof ctx> = {}): string[] =>
  attackModeIssues(a, { ...ctx, ...c }).map((i) => i.code);

const context = (title: string, line: number) => ({
  testId: title,
  titlePath: [title],
  file: 'tests/customer.spec.ts',
  line,
  project: 'customer',
});
const defaults = resolveConfig({});
if (!defaults.ok) throw new Error('config');
const keys = createKeyBuilder(defaults.config.normalization, { baseOrigins: [APP] });
const template = (method: string, path: string, line: number): AttackTemplate => {
  const key = keys({ method, url: `${APP}${path}`, resourceType: 'document' });
  return {
    method,
    url: `${APP}${path}`,
    headers: [],
    endpointKey: key.ok ? key.key : '',
    origin: APP,
    project: 'customer',
    source: 'browser',
    context: context(path, line),
  };
};

function mapOptions(a: ResolvedAttack = attack()) {
  const redactor = new Redactor({ salt: 'salt' });
  return {
    attack: a,
    templates: [template('GET', '/attack/search?q=tea', 3), template('GET', '/api/items?id=1', 8)],
    keyOf: (method: string, url: string) => {
      const origin = canonicalOrigin(url);
      const key = keys({ method, url, resourceType: 'xhr' });
      return origin === null || !key.ok ? null : { origin, key: key.key };
    },
    redact: (text: string) => redactor.text(text),
  };
}

describe('attack options and checks (19, chapter 4)', () => {
  test('the modes attack and attack-baseline exist (19-REQ-01)', () => {
    expect(readMode({ PW_SEC_MODE: 'attack' })).toEqual({ ok: true, mode: 'attack' });
    expect(readMode({ PW_SEC_MODE: 'Attack-Baseline' })).toEqual({
      ok: true,
      mode: 'attack-baseline',
    });
  });

  test('defaults of the table and no default origin (19-REQ-02, R-05)', () => {
    const a = resolveAttack(undefined);
    expect(a.allowedOrigins).toEqual([]);
    expect(a.methods).toEqual(['GET', 'HEAD', 'OPTIONS']);
    expect([a.maxDurationMinutes, a.maxRequests, a.maxRps]).toEqual([30, 2000, 10]);
    expect(a.image).toBe('zaproxy/zap-stable');
    expect(a.zapUrl).toBeNull();
  });

  test('04-AC-09 19-REQ-02 attack without allowed origins is an error before the tests', () => {
    expect(codes(resolveAttack({}))).toEqual(['ATTACK_ORIGINS_REQUIRED']);
    expect(codes(attack())).toEqual([]);
  });

  test('19-REQ-02 the production block list: denyOrigins always wins', () => {
    expect(codes(resolveAttack({ allowedOrigins: ['https://www.shop.example'] }))).toEqual([
      'ATTACK_ORIGIN_DENIED',
    ]);
    expect(
      codes(
        resolveAttack({
          allowedOrigins: ['https://shop.example'],
          iUnderstandThisIsNotProduction: true,
        }),
      ),
    ).toEqual([]);
    expect(
      codes(
        attack({
          allowedOrigins: [APP],
          denyOrigins: [APP],
          iUnderstandThisIsNotProduction: true,
        }),
      ),
    ).toEqual(['ATTACK_ORIGIN_DENIED']);
  });

  test('19-REQ-05 a local origin needs Linux or attack.zapUrl', () => {
    expect(codes(attack(), { platform: 'darwin' })).toEqual(['ATTACK_LOCAL_ORIGIN_UNSUPPORTED']);
    expect(codes(attack(), { platform: 'win32' })).toEqual(['ATTACK_LOCAL_ORIGIN_UNSUPPORTED']);
    expect(codes(attack({ zapUrl: 'http://127.0.0.1:8090' }), { platform: 'darwin' })).toEqual([]);
  });

  test('17-REQ-14 attack in shards and an unknown role are errors', () => {
    expect(codes(attack(), { sharded: true })).toEqual(['ATTACK_SHARDED']);
    expect(codes(attack({ role: 'admin' }))).toEqual(['ATTACK_ROLE_UNKNOWN']);
    expect(codes(attack({ role: 'anonymous' }))).toEqual([]);
    expect(attackRole(attack(), ['customer', 'admin'])).toBe('customer');
    expect(attackRole(attack(), [])).toBe('anonymous');
  });

  test('validation of attack.* and of zap.<id> rule settings (03-REQ-02, 19-REQ-09)', () => {
    expect(validateConfig({ attack: { allowedOrigins: [APP], methods: ['GET', 'POST'] } })).toEqual(
      [],
    );
    const issues = validateConfig({
      attack: {
        allowedOrigins: ['https://*.shop.example'],
        methods: ['TRACE'],
        strength: 'insane',
        zapUrl: 'http://127.0.0.1:8090/path',
        foo: 1,
      },
      rules: { 'zap.40012': 'off', 'zap.40018': { severity: 'low' }, 'zap.x1': 'off' },
    } as never).map((i) => i.path);
    expect(issues).toEqual(
      expect.arrayContaining([
        'attack.allowedOrigins[0]',
        'attack.methods',
        'attack.strength',
        'attack.zapUrl',
        'attack.foo',
        'rules.zap.x1',
      ]),
    );
    expect(issues).not.toContain('rules.zap.40012');
    expect(
      validateConfig({ rules: { 'zap.40012': { options: { a: 1 } } } } as never).map((i) => i.code),
    ).toEqual(['CONFIG_UNKNOWN_OPTION']);
    const resolved = resolveConfig({
      rules: { 'zap.40012': 'off', 'zap.40018': { severity: 'low' } },
    });
    expect(resolved.ok && resolved.config.attack.rules).toEqual({
      'zap.40012': { enabled: false },
      'zap.40018': { enabled: true, severity: 'low' },
    });
  });

  test('the Attack row of the banner (19-REQ-01)', () => {
    expect(attackBannerText(attack(), 'customer')).toBe(
      `ZAP docker zaproxy/zap-stable · origins ${APP} · role customer · budget 30 min, 2000 requests, 10 rps`,
    );
  });
});

describe('request bodies of attack templates (19-REQ-03, 19 chapter 11a)', () => {
  const r = {
    redactor: new Redactor({ salt: 'salt' }),
    names: new Set(['token', 'session']),
  };

  test('credential fields of JSON and forms are redacted, then the evidence redaction', () => {
    const json = templateBody(
      JSON.stringify({
        user: { email: 'bob@shop.example', password: 'Hunter2!', apiKey: 'k' },
        items: [{ sku: 'TEA-1', token: 't' }],
        note: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlLXZhbHVl',
      }),
      'application/json; charset=utf-8',
      10_000,
      r,
    );
    const parsed = JSON.parse(json ?? '{}');
    expect(parsed.user.password).toBe('[redacted]');
    expect(parsed.user.apiKey).toBe('[redacted]');
    expect(parsed.items[0]).toEqual({ sku: 'TEA-1', token: '[redacted]' });
    expect(parsed.user.email).toMatch(/^\[email sha256:[0-9a-f]{6}\]$/);
    expect(json).not.toContain('Hunter2');
    expect(json).not.toContain('bob@shop.example');
    expect(json).not.toContain('c2lnbmF0dXJlLXZhbHVl');

    const form = templateBody(
      'q=tea&passwd=s3cret&session=abc',
      'application/x-www-form-urlencoded',
      10_000,
      r,
    );
    expect(new URLSearchParams(form).get('q')).toBe('tea');
    expect(new URLSearchParams(form).get('passwd')).toBe('[redacted]');
    expect(new URLSearchParams(form).get('session')).toBe('[redacted]');
  });

  test('other types, broken JSON and too long bodies are not kept', () => {
    expect(templateBody('--x\r\n', 'multipart/form-data; boundary=x', 10_000, r)).toBeUndefined();
    expect(templateBody('{"a":', 'application/json', 10_000, r)).toBeUndefined();
    expect(templateBody('{"a":"bbbbbbbb"}', 'application/json', 5, r)).toBeUndefined();
    expect(templateBody(null, 'application/json', 10_000, r)).toBeUndefined();
  });
});

describe('mapping of ZAP alerts (19-REQ-08)', () => {
  test('alerts → zap.<pluginId> findings with fingerprints by endpoint key and parameter', () => {
    const out = mapAlerts(alerts, mapOptions());
    expect(out.findings.map((f) => f.fingerprint).sort()).toEqual([
      'zap.40012|endpoint|GET /attack/search?q|q',
      'zap.40018|endpoint|GET /api/items?id|id',
      'zap.40026|endpoint|GET /attack/search?q|q',
      'zap.90022|endpoint|GET /api/items?id',
    ]);
    expect(mapAlerts([...alerts].reverse(), mapOptions()).findings).toEqual(out.findings);
    // Two SQL injection alerts of one parameter are one finding (07, chapter 4).
    expect(out.findings.find((f) => f.ruleId === 'zap.40018')?.occurrences).toBe(2);
    expect(out.alerts).toEqual({ mapped: 5, falsePositive: 1, off: 0 });
    const xss = out.findings.find((f) => f.ruleId === 'zap.40012');
    expect(xss).toMatchObject({
      severity: 'high',
      confidence: 'medium',
      scope: 'endpoint',
      subject: 'GET /attack/search?q',
      discriminator: 'q',
      location: { origin: APP, endpointKey: 'GET /attack/search?q', param: 'q' },
      message: 'Cross Site Scripting (Reflected) in parameter q',
      sources: ['browser'],
    });
    expect(xss?.firstSeen.titlePath).toEqual(['/attack/search?q=tea']);
    expect(xss?.evidence[0]?.kind).toBe('attack');
    expect(xss?.evidence[0]?.snippet).toContain('attack: </h1><scrIpt>alert(1);</scRipt><h1>');
    // The evidence is redacted like every other (07-REQ-13).
    const error = out.findings.find((f) => f.ruleId === 'zap.90022');
    expect(error?.evidence[0]?.snippet).not.toContain('admin@shop.example');
    expect(error?.confidence).toBe('medium');
    expect(error?.severity).toBe('low');
  });

  test('rule descriptions with the ZAP docs, CWE and OWASP (19-REQ-10)', () => {
    const rules = mapAlerts(alerts, mapOptions()).rules;
    expect(rules.map((r) => r.id)).toEqual(['zap.40012', 'zap.40018', 'zap.40026', 'zap.90022']);
    expect(rules[0]).toMatchObject({
      name: 'Cross Site Scripting (Reflected)',
      helpUri: 'https://www.zaproxy.org/docs/alerts/40012/',
      cwe: [79],
      owasp: 'A05:2025',
    });
    expect(owaspOf({ OWASP_2021_A03: 'x' })).toBe('A03:2021');
    expect(owaspOf({})).toBeNull();
    expect(
      ['Confirmed', 'High', 'Medium', 'Low', 'False Positive', '4', '0'].map(confidenceOf),
    ).toEqual(['high', 'high', 'medium', 'low', null, 'high', null]);
  });

  test('rules["zap.<id>"]: off drops the alert, severity and confidence override it', () => {
    const resolved = resolveConfig({
      attack: { allowedOrigins: [APP] },
      rules: { 'zap.40026': 'off', 'zap.40018': { severity: 'critical', confidence: 'high' } },
    });
    if (!resolved.ok) throw new Error('config');
    const out = mapAlerts(alerts, mapOptions(resolved.config.attack));
    expect(out.findings.some((f) => f.ruleId === 'zap.40026')).toBe(false);
    expect(out.alerts.off).toBe(1);
    expect(out.findings.find((f) => f.ruleId === 'zap.40018')).toMatchObject({
      severity: 'critical',
      confidence: 'high',
    });
  });

  test('an alert outside attack.allowedOrigins is not a finding (18-REQ-04)', () => {
    const outside: ZapAlert = {
      ...(alerts[0] as ZapAlert),
      url: 'https://127.0.0.1:4431/attack/search?q=%3Cscript%3E',
    };
    expect(mapAlerts([outside], mapOptions()).findings).toEqual([]);
  });
});

describe('coverage of zap.* baseline entries (19-REQ-09)', () => {
  const baseline = {
    schemaVersion: 1 as const,
    generatedBy: 'test',
    findings: {
      'zap.40012|endpoint|GET /attack/search?q|q': {
        ruleId: 'zap.40012',
        subject: 'GET /attack/search?q',
        severity: 'high' as const,
        status: 'accepted' as const,
        addedAt: '2026-11-27',
      },
    },
  };

  test('19-AC-05 without a completed scan of the key the entry is not covered, never resolved', () => {
    const coverage = { ...emptyCoverage(), endpoints: { 'GET /attack/search?q': 3 } };
    const resolved = resolveConfig({});
    if (!resolved.ok) throw new Error('config');
    const enabled = new EnabledRules(resolved.config);
    expect(resolveEntries(baseline, [], coverage, enabled).notCovered).toHaveLength(1);
    expect(
      resolveEntries(baseline, [], coverage, enabled, new Set(), new Set(['GET /attack/search?q']))
        .resolved,
    ).toHaveLength(1);
    expect(KNOWN_RULE_IDS.has('zap.40012')).toBe(true);
    expect(KNOWN_RULE_IDS.has('zap.x')).toBe(false);
    const off = resolveConfig({ rules: { 'zap.40012': 'off' } });
    if (!off.ok) throw new Error('config');
    expect(new EnabledRules(off.config).has('zap.40012')).toBe(false);
  });
});
