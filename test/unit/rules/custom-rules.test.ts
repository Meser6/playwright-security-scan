// Custom rules (16): defineRule(), validation, presets, execution and reports.
import { describe, expect, test } from 'vitest';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  AnalysisCache,
  TestCollector,
  userStackLine,
} from '../../../src/collector/test-collector.ts';
import { Scope } from '../../../src/collector/scope.ts';
import { ConfigError, resolveConfig, validateConfig } from '../../../src/core/config/index.ts';
import type {
  ResolvedSecurityConfig,
  SecurityConfigInput,
} from '../../../src/core/config/index.ts';
import { adaptCustomRule } from '../../../src/core/custom/adapt.ts';
import { Redactor } from '../../../src/core/fingerprint/index.ts';
import { buildJunit } from '../../../src/core/report/junit.ts';
import { buildSarif } from '../../../src/core/report/sarif.ts';
import { formatBanner } from '../../../src/core/report/console.ts';
import { rulesOf } from '../../../src/core/rules/all.ts';
import { parseBaseline } from '../../../src/core/baseline/index.ts';
import { RULE_IDS } from '../../../src/core/manifest/rules.ts';
import type { ResponseRecord, RunReport } from '../../../src/core/types/index.ts';
import {
  builtinRuleIds,
  decodeJwt,
  defineRule,
  getHeader,
  getHeaders,
  parseSetCookie,
} from '../../../src/entries/rules.ts';
import type { RuleDefinition } from '../../../src/entries/rules.ts';

const ref = { testId: 't1', titlePath: ['t'], file: 'a.spec.ts', line: 1, project: 'p' };
const record = (over: Partial<ResponseRecord> = {}): ResponseRecord => ({
  kind: 'response',
  id: 1,
  source: 'api',
  method: 'GET',
  url: 'https://app.test/api/me',
  endpointKey: 'GET /api/me',
  origin: 'https://app.test',
  resourceType: 'api',
  isNavigation: false,
  requestHeaders: [],
  status: 200,
  responseHeaders: [{ name: 'content-type', value: 'application/json' }],
  context: ref,
  ...over,
});

const definition = (over: Partial<RuleDefinition> = {}): RuleDefinition => ({
  id: 'custom.request-id-missing',
  defaultSeverity: 'low',
  defaultConfidence: 'high',
  scope: 'endpoint',
  appliesTo: { sources: ['api', 'browser'], resourceTypes: ['api', 'xhr', 'fetch'] },
  options: { header: 'x-request-id' },
  docs: {
    title: 'API response without x-request-id',
    why: 'Without a request id incidents cannot be traced across services.',
    fix: 'Add the header in the gateway.',
    url: 'https://wiki.example.com/security/request-id',
  },
  check(input, ctx) {
    if (input.kind !== 'response') return [];
    if (getHeader(input, ctx.options.header as string) !== undefined) return [];
    return [{ subject: input.endpointKey, message: `No ${String(ctx.options.header)} header` }];
  },
  ...over,
});

const requestId = defineRule(definition());

const resolved = (input: SecurityConfigInput): ResolvedSecurityConfig => {
  const r = resolveConfig(input);
  if (!r.ok) throw new Error(r.issues.map((i) => i.message).join('\n'));
  return r.config;
};

const scope = new Scope({
  baseOrigins: ['https://app.test'],
  includeBaseURL: true,
  origins: [],
  exclude: [],
});

/** Findings of custom rules only; the built-in catalog runs too. */
const custom = (c: TestCollector) => c.findings().filter((f) => f.ruleId.startsWith('custom.'));

function collector(cfg: ResolvedSecurityConfig, cache = new AnalysisCache()): TestCollector {
  return new TestCollector({
    config: cfg,
    rules: rulesOf(cfg),
    scope,
    redactor: new Redactor({ salt: 's' }),
    cache,
    test: ref,
  });
}

const codes = (input: unknown): string[] => validateConfig(input).map((i) => i.code);

describe('defineRule() and the entry point (16-REQ-01 … 16-REQ-03)', () => {
  test('returns a frozen rule with the definition', () => {
    expect(Object.isFrozen(requestId)).toBe(true);
    expect(requestId.id).toBe('custom.request-id-missing');
    expect(() => {
      (requestId as { id: string }).id = 'custom.other';
    }).toThrow();
  });

  test('throws a ConfigError with every problem of the definition', () => {
    const bad = { ...definition(), id: 'header.mine', defaultSeverity: 'huge' } as unknown;
    let error: unknown;
    try {
      defineRule(bad as RuleDefinition);
    } catch (e) {
      error = e;
    }
    expect(error).toBeInstanceOf(ConfigError);
    expect((error as ConfigError).issues.map((i) => i.path)).toEqual([
      'defineRule(header.mine).id',
      'defineRule(header.mine).defaultSeverity',
    ]);
  });

  test('a custom rule with testEnd gets the end-of-test traffic once per test, without values (16, chapter 12a)', () => {
    const inputs: string[] = [];
    const rule = defineRule(
      definition({
        id: 'custom.login-count',
        appliesTo: { testEnd: true },
        check(input) {
          inputs.push(input.kind);
          if (input.kind !== 'test-end') return [];
          const logins = input.requests.filter((r) => r.isLoginCandidate);
          return logins.map((r) => ({ subject: r.endpointKey, message: `login ${r.endpointKey}` }));
        },
      }),
    );
    const c = collector(resolved({ rules: { custom: [rule] } }));
    expect(c.wantsTraffic).toBe(true);
    const login = record({
      source: 'browser',
      id: c.nextSequence(),
      method: 'POST',
      url: 'https://app.test/api/login',
      endpointKey: 'POST /api/login',
      resourceType: 'fetch',
      requestHeaders: [{ name: 'cookie', value: 'sid=Zq8xK2mP9vL4tR7wY1nB3c' }],
    });
    c.analyzeRecord(login);
    c.addTraffic(login, null);
    expect(inputs).toEqual([]);
    c.analyzeTestEnd();
    expect(inputs).toEqual(['test-end']);
    const found = custom(c);
    expect(found.map((f) => [f.fingerprint, f.location.origin])).toEqual([
      ['custom.login-count|endpoint|POST /api/login', 'https://app.test'],
    ]);
    // Run once: the traffic is consumed.
    c.analyzeTestEnd();
    expect(inputs).toEqual(['test-end']);
  });

  test('appliesTo.testEnd must be a boolean; testEnd alone is an input', () => {
    expect(() =>
      defineRule(
        definition({ appliesTo: { testEnd: 'yes' } as unknown as RuleDefinition['appliesTo'] }),
      ),
    ).toThrow(/testEnd/);
    expect(() =>
      defineRule(definition({ appliesTo: { records: false, testEnd: true } })),
    ).not.toThrow();
    expect(
      adaptCustomRule(defineRule(definition({ appliesTo: { testEnd: true } }))).appliesTo,
    ).toEqual({
      records: false,
      testEnd: true,
    });
  });

  test('helpers: headers of either side, Set-Cookie, JWT and the built-in ids', () => {
    const r = record({
      requestHeaders: [{ name: 'x-trace', value: 'a' }],
      responseHeaders: [
        { name: 'set-cookie', value: 'a=1; Secure' },
        { name: 'set-cookie', value: 'b=2; HttpOnly' },
      ],
    });
    expect(getHeaders(r, 'Set-Cookie')).toEqual(['a=1; Secure', 'b=2; HttpOnly']);
    expect(getHeader(r, 'X-TRACE')).toBeUndefined();
    expect(getHeaders(r, 'X-TRACE', 'request')).toEqual(['a']);
    expect(parseSetCookie('sid=v; Domain=app.test; SameSite=Lax; Secure')).toMatchObject({
      name: 'sid',
      domain: 'app.test',
      sameSite: 'Lax',
      secure: true,
      httpOnly: false,
    });
    expect(decodeJwt('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1MSJ9.c2ln')?.payload).toEqual({ sub: 'u1' });
    expect(builtinRuleIds).toEqual(RULE_IDS);
    expect(builtinRuleIds.some((id) => id.startsWith('custom.'))).toBe(false);
  });
});

describe('16-AC-03 validation of rules.custom (16-REQ-04)', () => {
  test('a rule not made with defineRule() is CONFIG_INVALID_RULE', () => {
    const issues = validateConfig({ rules: { custom: [definition()] } });
    expect(issues.map((i) => i.code)).toEqual(['CONFIG_INVALID_RULE']);
    expect(issues[0]?.message).toMatch(/defineRule\(\)/);
  });

  test.each([
    'id',
    'defaultSeverity',
    'defaultConfidence',
    'scope',
    'check',
    'docs.title',
    'docs.why',
    'docs.fix',
  ])('a missing %s is CONFIG_INVALID_RULE with the field name', (field) => {
    const [top, sub] = field.split('.') as [string, string | undefined];
    const rule: Record<string, unknown> =
      sub === undefined
        ? { ...requestId, [top]: undefined }
        : { ...requestId, docs: { ...requestId.docs, [sub]: undefined } };
    const issues = validateConfig({ rules: { custom: [rule] } });
    expect(issues.map((i) => i.code)).toEqual(['CONFIG_INVALID_RULE']);
    expect(issues[0]?.path).toBe(`rules.custom[0].${field}`);
  });

  test('an id outside custom.<name> is CONFIG_INVALID_RULE with the pattern', () => {
    for (const id of ['header.mine', 'custom.Upper', 'custom.', `custom.${'a'.repeat(49)}`]) {
      const issues = validateConfig({ rules: { custom: [{ ...requestId, id }] } });
      expect(issues.map((i) => i.code)).toEqual(['CONFIG_INVALID_RULE']);
      expect(issues[0]?.hint).toMatch(/\[a-z0-9\]\[a-z0-9-\]\{0,47\}/);
    }
  });

  test('the same id twice is CONFIG_DUPLICATE_RULE', () => {
    expect(codes({ rules: { custom: [requestId, requestId] } })).toEqual(['CONFIG_DUPLICATE_RULE']);
  });

  test('rules["custom.x"] without the rule in rules.custom is CONFIG_UNKNOWN_RULE with the closest name', () => {
    const issues = validateConfig({
      rules: { custom: [requestId], 'custom.request-id-mising': 'off' },
    });
    expect(issues.map((i) => i.code)).toEqual(['CONFIG_UNKNOWN_RULE']);
    expect(issues[0]?.message).toContain('Did you mean "custom.request-id-missing"?');
    expect(codes({ rules: { 'custom.request-id-missing': 'off' } })).toEqual([
      'CONFIG_UNKNOWN_RULE',
    ]);
  });

  test('an unknown option or an option of another type is reported as for built-in rules', () => {
    expect(
      codes({
        rules: {
          custom: [requestId],
          'custom.request-id-missing': { options: { headr: 'x' } },
        },
      }),
    ).toEqual(['CONFIG_UNKNOWN_OPTION']);
    expect(
      codes({
        rules: { custom: [requestId], 'custom.request-id-missing': { options: { header: 1 } } },
      }),
    ).toEqual(['CONFIG_INVALID_TYPE']);
  });

  test('rules.custom must be an array', () => {
    expect(codes({ rules: { custom: requestId } })).toEqual(['CONFIG_INVALID_TYPE']);
  });
});

describe('presets and settings (16-REQ-05)', () => {
  const medium = defineRule(definition({ id: 'custom.medium', defaultConfidence: 'medium' }));

  test('16-AC-05 rules["custom.x"]: "off" turns a rule off; minimal skips a medium-confidence rule', () => {
    const off = resolved({ rules: { custom: [requestId], 'custom.request-id-missing': 'off' } });
    expect(off.rules['custom.request-id-missing']?.enabled).toBe(false);
    const c = collector(off);
    c.analyzeRecord(record());
    expect(custom(c)).toEqual([]);

    const minimal = resolved({ rules: { preset: 'minimal', custom: [requestId, medium] } });
    expect(minimal.rules['custom.request-id-missing']?.enabled).toBe(true);
    expect(minimal.rules['custom.medium']?.enabled).toBe(false);
    const m = collector(minimal);
    m.analyzeRecord(record());
    expect(custom(m).map((f) => f.ruleId)).toEqual(['custom.request-id-missing']);
  });

  test('strict raises low/high to medium; severity and options are overridden', () => {
    expect(
      resolved({ rules: { preset: 'strict', custom: [requestId] } }).rules[
        'custom.request-id-missing'
      ]?.severity,
    ).toBe('medium');
    const cfg = resolved({
      rules: {
        custom: [requestId],
        'custom.request-id-missing': { severity: 'high', options: { header: 'x-correlation-id' } },
      },
    });
    const c = collector(cfg);
    c.analyzeRecord(record({ responseHeaders: [{ name: 'x-request-id', value: '1' }] }));
    expect(custom(c)).toMatchObject([
      { severity: 'high', confidence: 'high', message: 'No x-correlation-id header' },
    ]);
  });
});

describe('execution (16-REQ-07 … 16-REQ-10)', () => {
  test('a custom rule finding has the package fields and the fingerprint of 07-REQ-05', () => {
    const cfg = resolved({ rules: { custom: [requestId] } });
    const c = collector(cfg);
    c.analyzeRecord(record());
    c.analyzeRecord(record({ responseHeaders: [{ name: 'x-request-id', value: '1' }] }));
    const [f] = custom(c);
    expect(f).toMatchObject({
      ruleId: 'custom.request-id-missing',
      scope: 'endpoint',
      severity: 'low',
      confidence: 'high',
      subject: 'GET /api/me',
      location: { origin: 'https://app.test', endpointKey: 'GET /api/me' },
      evidence: [],
      sources: ['api'],
      occurrences: 1,
    });
    expect(f?.fingerprint).toBe('custom.request-id-missing|endpoint|GET /api/me');
    expect(c.coverage.rulesRun['custom.request-id-missing']).toBe(2);
  });

  test('custom rules run after the built-in ones, in the order of rules.custom', () => {
    const order: string[] = [];
    const a = defineRule(definition({ id: 'custom.b', check: () => (order.push('b'), []) }));
    const b = defineRule(definition({ id: 'custom.a', check: () => (order.push('a'), []) }));
    const cfg = resolved({ rules: { custom: [a, b] } });
    expect(
      rulesOf(cfg)
        .slice(-2)
        .map((r) => r.id),
    ).toEqual(['custom.b', 'custom.a']);
    collector(cfg).analyzeRecord(record());
    expect(order).toEqual(['b', 'a']);
  });

  test('events: a rule on the cookie jar gets only events', () => {
    const jar = defineRule(
      definition({
        id: 'custom.cookie-prefix',
        scope: 'cookie',
        appliesTo: { events: ['cookie-jar'] },
        check: (input) =>
          input.kind === 'cookie-jar'
            ? input.cookies
                .filter((k) => !k.name.startsWith('__Host-'))
                .map((k) => ({ subject: `${k.name}@${k.domain}`, message: 'no __Host- prefix' }))
            : [],
      }),
    );
    const c = collector(resolved({ rules: { custom: [jar] } }));
    c.analyzeRecord(record());
    c.analyzeEvent({
      kind: 'cookie-jar',
      cookies: [
        {
          name: 'sid',
          value: 'v',
          domain: 'app.test',
          path: '/',
          secure: true,
          httpOnly: true,
          sameSite: 'Lax',
          expires: -1,
          origin: 'https://app.test',
        },
      ],
      context: ref,
    });
    expect(custom(c).map((f) => [f.fingerprint, f.location.origin])).toEqual([
      ['custom.cookie-prefix|cookie|sid@app.test', 'https://app.test'],
    ]);
  });

  test('needsBody: true reads the bodies of the resource types of the rule', () => {
    expect(adaptCustomRule(defineRule(definition({ needsBody: true }))).needsBody).toEqual([
      'api',
      'xhr',
      'fetch',
    ]);
    expect(
      adaptCustomRule(defineRule(definition({ appliesTo: undefined, needsBody: true }))).needsBody,
    ).toEqual(['document', 'script', 'stylesheet', 'xhr', 'fetch', 'api']);
    const cfg = resolved({ rules: { custom: [defineRule(definition({ needsBody: ['api'] }))] } });
    expect(collector(cfg).bodyTypes.has('api')).toBe(true);
  });

  test('16-REQ-09 an exception is CUSTOM_RULE_ERROR (error) with the id; the rule is off for the test', () => {
    let calls = 0;
    const broken = defineRule(
      definition({
        id: 'custom.broken',
        check: () => {
          calls += 1;
          throw new Error('cannot read header');
        },
      }),
    );
    const c = collector(resolved({ rules: { custom: [broken, requestId] } }));
    c.analyzeRecord(record());
    c.analyzeRecord(record());
    expect(calls).toBe(1);
    const [d] = c.diagnostics();
    expect(d).toMatchObject({ code: 'CUSTOM_RULE_ERROR', level: 'error', testId: 't1' });
    expect(d?.message).toContain('custom rule custom.broken threw');
    expect(d?.message).toContain('cannot read header');
    // The first stack line from the user's file.
    expect(d?.message).toMatch(/\(at .*custom-rules\.test\.ts:\d+:\d+\)?/);
    expect(custom(c).map((f) => f.ruleId)).toEqual(['custom.request-id-missing']);
  });

  test('a result that is not an array of findings is CUSTOM_RULE_ERROR', () => {
    const bad = defineRule(
      definition({
        id: 'custom.bad-result',
        check: () => [{ subject: '', message: 'x' }],
      }),
    );
    const c = collector(resolved({ rules: { custom: [bad] } }));
    c.analyzeRecord(record());
    expect(c.diagnostics()[0]?.message).toContain('subject must be a non-empty string');
  });

  test('16-REQ-08 a promise is CUSTOM_RULE_ASYNC and the rule is off for the rest of the run in the worker', () => {
    let calls = 0;
    const asyncRule = defineRule(
      definition({
        id: 'custom.async',
        check: (() => {
          calls += 1;
          return Promise.resolve([]);
        }) as unknown as RuleDefinition['check'],
      }),
    );
    const cache = new AnalysisCache();
    const cfg = resolved({ rules: { custom: [asyncRule] } });
    const first = collector(cfg, cache);
    first.analyzeRecord(record());
    expect(first.diagnostics().map((d) => [d.code, d.level])).toEqual([
      ['CUSTOM_RULE_ASYNC', 'error'],
    ]);
    collector(cfg, cache).analyzeRecord(record());
    expect(calls).toBe(1);
  });

  test('16-AC-06 evidence of a custom rule is redacted (header redaction and the final filter)', () => {
    const secret = 'Sh0pSess10nV4lue9x7Kq2LmZ';
    const leaky = defineRule(
      definition({
        id: 'custom.leaky',
        check: (input) =>
          input.kind === 'response'
            ? [
                {
                  subject: input.endpointKey,
                  message: `session ${secret}`,
                  evidence: [
                    { kind: 'header', name: 'set-cookie', snippet: `theme=dark-pref-77; Secure` },
                    { kind: 'body', snippet: `{"token":"${secret}"}` },
                  ],
                },
              ]
            : [],
      }),
    );
    const c = collector(resolved({ rules: { custom: [leaky] } }));
    c.analyzeRecord(record());
    const text = JSON.stringify(custom(c));
    expect(text).not.toContain(secret);
    expect(text).not.toContain('dark-pref-77');
    expect(custom(c)[0]?.evidence[0]?.snippet).toMatch(
      /^theme=\[redacted sha256:[0-9a-f]{6}\]; Secure$/,
    );
  });
});

describe('baseline and reports (16-REQ-11, 16-REQ-12)', () => {
  const report = (ruleId: string): RunReport =>
    ({
      schemaVersion: 2,
      runId: 'r',
      startedAt: '2026-11-27T00:00:00.000Z',
      finishedAt: '2026-11-27T00:00:01.000Z',
      mode: 'scan',
      shards: null,
      authz: null,
      pkgVersion: '0.0.0',
      playwrightVersion: '1.57.0',
      scope: { origins: ['https://app.test'] },
      coverage: {} as RunReport['coverage'],
      findings: [
        {
          ruleId,
          severity: 'low',
          confidence: 'high',
          scope: 'endpoint',
          subject: 'GET /api/me',
          location: { origin: 'https://app.test' },
          evidence: [],
          message: 'No x-request-id header',
          fingerprint: `${ruleId}|endpoint|GET /api/me`,
          occurrences: 1,
          firstSeen: ref,
          tests: ['t1'],
          sources: ['api'],
          classification: 'new',
          blocking: true,
        },
      ],
      resolved: [],
      notCovered: [],
      testsWithoutTraffic: [],
      gate: { minSeverity: 'low', minConfidence: 'medium', failed: true, blocking: [] },
      diagnostics: [],
      outcome: { code: 1 } as RunReport['outcome'],
    }) as RunReport;

  test('a baseline entry of a rule no longer in rules.custom is BASELINE_RULE_OFF, not invalid', () => {
    const text = JSON.stringify({
      schemaVersion: 1,
      findings: {
        'custom.gone|endpoint|GET /': {
          ruleId: 'custom.gone',
          subject: 'GET /',
          severity: 'low',
          status: 'accepted',
          addedAt: '2026-11-27',
        },
      },
    });
    const parsed = parseBaseline(text, 'b.json', new Set(RULE_IDS), new Set(RULE_IDS));
    expect(parsed.ok).toBe(true);
    expect(parsed.diagnostics.map((d) => d.code)).toEqual(['BASELINE_RULE_OFF']);
  });

  test('16-AC-04 SARIF has the rule with the custom tag and docs.url; JUnit has a custom suite', () => {
    const cfg = resolved({ rules: { custom: [requestId] } });
    const rules = rulesOf(cfg);
    const sarif = buildSarif(report('custom.request-id-missing'), rules, {
      version: '0.0.0',
      includeAccepted: false,
    }) as {
      runs: { tool: { driver: { rules: Record<string, unknown>[] } }; results: unknown[] }[];
    };
    const rule = sarif.runs[0]?.tool.driver.rules.find((r) => r.id === 'custom.request-id-missing');
    expect(rule).toMatchObject({
      helpUri: 'https://wiki.example.com/security/request-id',
      properties: { tags: ['security', 'custom'] },
    });
    expect(sarif.runs[0]?.results).toHaveLength(1);
    const noUrl = defineRule(
      definition({ id: 'custom.no-url', docs: { title: 't', why: 'w', fix: 'f' } }),
    );
    const plain = buildSarif(
      report('custom.no-url'),
      rulesOf(resolved({ rules: { custom: [noUrl] } })),
      {
        version: '0.0.0',
        includeAccepted: false,
      },
    ) as { runs: { tool: { driver: { rules: Record<string, unknown>[] } } }[] };
    expect(plain.runs[0]?.tool.driver.rules.at(-1)).not.toHaveProperty('helpUri');

    const junit = buildJunit(report('custom.request-id-missing'), rules, {
      includeAccepted: false,
      failOnExpired: true,
    });
    expect(junit).toContain('<testsuite name="custom" tests="1" failures="1"');
    expect(junit).toContain('classname="pw-sec.custom.custom.request-id-missing"');
  });

  test('the start banner counts the custom rules', () => {
    const lines = formatBanner(
      {
        mode: 'scan',
        scope: ['https://app.test'],
        enabledRules: 47,
        customRules: 3,
        preset: 'recommended',
        minSeverity: 'medium',
        minConfidence: 'medium',
        baselinePath: 'security-baseline.json',
        baselineEntries: null,
        reportPath: 'reports/pw-sec/report.html',
        notes: [],
      },
      { width: 100, color: false, ascii: true },
    );
    expect(lines.join('\n')).toContain('47 enabled (preset recommended, 3 custom)');
  });
});

describe('the stack line of CUSTOM_RULE_ERROR (16-REQ-09)', () => {
  const at = (line: string): string | undefined => {
    const error = new Error('x');
    error.stack = `Error: x\n    at check (/srv/node_modules/playwright-security-scan/dist/fixture.js:1:1)\n    ${line}`;
    return userStackLine(error);
  };

  test('a path or file URL under the working directory becomes relative', () => {
    const cwd = process.cwd();
    expect(at(`at Object.check (${join(cwd, 'rules', 'a b.ts')}:3:9)`)).toBe(
      'at Object.check (rules/a b.ts:3:9)',
    );
    expect(at(`at Object.check (${pathToFileURL(join(cwd, 'rules', 'a b.ts')).href}:3:9)`)).toBe(
      'at Object.check (rules/a b.ts:3:9)',
    );
    expect(at(`at ${join(cwd, 'r.ts')}:1:2`)).toBe('at r.ts:1:2');
  });

  test('a path outside the working directory stays absolute', () => {
    expect(at('at check (/elsewhere/r.ts:1:2)')).toBe('at check (/elsewhere/r.ts:1:2)');
  });
});
