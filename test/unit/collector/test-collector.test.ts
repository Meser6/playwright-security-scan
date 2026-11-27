import { describe, expect, test } from 'vitest';
import { AnalysisCache, TestCollector } from '../../../src/collector/test-collector.ts';
import { Scope } from '../../../src/collector/scope.ts';
import { bodySkipReason, typeAllowed } from '../../../src/collector/body.ts';
import { cspListenerScript } from '../../../src/collector/page-script.ts';
import { resolveConfig } from '../../../src/core/config/index.ts';
import type { ResolvedSecurityConfig } from '../../../src/core/config/index.ts';
import { Redactor } from '../../../src/core/fingerprint/index.ts';
import { BUILT_IN_RULES } from '../../../src/core/rules/index.ts';
import type { BuiltInRule } from '../../../src/core/rules/index.ts';
import type { ResponseRecord } from '../../../src/core/types/index.ts';

const config = (input = {}): ResolvedSecurityConfig => {
  const r = resolveConfig(input);
  if (!r.ok) throw new Error('bad config');
  return r.config;
};
const scope = new Scope({
  baseOrigins: ['https://app.test'],
  includeBaseURL: true,
  origins: [],
  exclude: [],
});
const ctxRef = { testId: 't1', titlePath: ['t'], file: 'a.spec.ts', line: 1, project: 'p' };

const record = (over: Partial<ResponseRecord> = {}): ResponseRecord => ({
  kind: 'response',
  id: 1,
  source: 'browser',
  method: 'GET',
  url: 'https://app.test/',
  endpointKey: 'GET /',
  origin: 'https://app.test',
  resourceType: 'document',
  isNavigation: true,
  requestHeaders: [],
  status: 200,
  responseHeaders: [{ name: 'content-type', value: 'text/html' }],
  context: ctxRef,
  ...over,
});

const collector = (rules: readonly BuiltInRule[], cfg = config()): TestCollector =>
  new TestCollector({
    config: cfg,
    rules,
    scope,
    redactor: new Redactor({ salt: 's' }),
    cache: new AnalysisCache(),
    test: ctxRef,
  });

const xcto = BUILT_IN_RULES.find((r) => r.id === 'header.xcto-missing') as BuiltInRule;

describe('TestCollector (05, chapter 6)', () => {
  test('05-REQ-15 a throwing rule becomes RULE_ERROR and is off for the rest of the test (P-08)', () => {
    let calls = 0;
    const broken: BuiltInRule = {
      ...xcto,
      id: 'header.csp-missing',
      manifest: { ...xcto.manifest, id: 'header.csp-missing' },
      check: () => {
        calls += 1;
        throw new Error('boom');
      },
    };
    const c = collector([broken, xcto]);
    c.analyzeRecord(record());
    c.analyzeRecord(record());
    expect(calls).toBe(1);
    expect(c.diagnostics().map((d) => d.code)).toEqual(['RULE_ERROR']);
    expect(c.findings().map((f) => f.ruleId)).toEqual(['header.xcto-missing']);
    expect(c.findings()[0]?.occurrences).toBe(2);
  });

  test('limits.maxFindingsPerRule stops a rule and reports it', () => {
    const c = collector([xcto], config({ limits: { maxFindingsPerRule: 2 } }));
    for (let i = 0; i < 5; i++) c.analyzeRecord(record());
    expect(c.findings()[0]?.occurrences).toBe(2);
    expect(c.diagnostics().map((d) => d.code)).toEqual(['RULE_FINDINGS_LIMIT']);
  });

  test('disabled rules do not run', () => {
    const c = collector([xcto], config({ rules: { 'header.xcto-missing': 'off' } }));
    c.analyzeRecord(record());
    expect(c.findings()).toEqual([]);
    expect(c.coverage.rulesRun).toEqual({});
  });

  test('coverage counts records, documents, origins, endpoints and assets', () => {
    const c = collector([]);
    c.analyzeRecord(record());
    c.analyzeRecord(
      record({
        resourceType: 'script',
        url: 'https://app.test/main.a1b2c3d4.js',
        endpointKey: 'GET /main.a1b2c3d4.js',
      }),
    );
    c.analyzeRecord(record({ source: 'api', resourceType: 'api', endpointKey: 'GET /api' }));
    expect(c.coverage).toMatchObject({
      responses: 3,
      apiResponses: 1,
      documents: 1,
      origins: { 'https://app.test': { responses: 3, documents: 1 } },
      endpoints: { 'GET /': 1, 'GET /main.a1b2c3d4.js': 1, 'GET /api': 1 },
      assets: ['https://app.test/main.*.js'],
    });
  });

  test('02-REQ-05 an attachment over 256 KB keeps one evidence item per finding', () => {
    const big: BuiltInRule = {
      ...xcto,
      check: (input) =>
        Array.from({ length: 3000 }, (_, i) => ({
          ruleId: 'header.xcto-missing',
          severity: 'low' as const,
          confidence: 'high' as const,
          scope: 'endpoint' as const,
          subject: `GET /x${i}`,
          location: { origin: 'https://app.test' },
          evidence: [1, 2, 3].map((n) => ({
            kind: 'body' as const,
            snippet: `${n}-${'e'.repeat(60)}`,
          })),
          message: 'm',
        })).filter(() => 'status' in input),
    };
    const c = collector([big], config({ limits: { maxFindingsPerRule: 5000 } }));
    c.analyzeRecord(record());
    const doc = JSON.parse(c.attachment()) as {
      findings: { evidence: unknown[] }[];
      diagnostics: { code: string }[];
    };
    expect(doc.findings.every((f) => f.evidence.length === 1)).toBe(true);
    expect(doc.diagnostics.map((d) => d.code)).toContain('ATTACHMENT_TRUNCATED');
  });
});

describe('scope and bodies (05, chapters 4 and 5.2)', () => {
  test('05-REQ-04 baseURL origins, extra origins with patterns, exclusions', () => {
    const s = new Scope({
      baseOrigins: ['https://app.test'],
      includeBaseURL: true,
      origins: ['https://*.api.test'],
      exclude: ['https://ads.api.test'],
    });
    expect(s.has('https://app.test')).toBe(true);
    expect(s.has('https://v1.api.test')).toBe(true);
    expect(s.has('https://ads.api.test')).toBe(false);
    expect(s.has('https://cdn.other.test')).toBe(false);
    expect(
      new Scope({
        baseOrigins: ['https://app.test'],
        includeBaseURL: false,
        origins: [],
        exclude: [],
      }).has('https://app.test'),
    ).toBe(false);
  });

  test('05-REQ-10 and 05-REQ-13 skip reasons', () => {
    const base = {
      resourceType: 'fetch',
      status: 200,
      contentType: 'application/json; charset=utf-8',
      contentLength: '100',
      maxBodyBytes: 1000,
      allowedTypes: ['application/json', '*+json'],
      wanted: true,
    };
    expect(bodySkipReason(base)).toBeNull();
    expect(bodySkipReason({ ...base, resourceType: 'image' })).toBe('resource-type');
    expect(bodySkipReason({ ...base, status: 204 })).toBe('status');
    expect(bodySkipReason({ ...base, status: 302 })).toBe('status');
    expect(bodySkipReason({ ...base, wanted: false })).toBe('no-rule');
    expect(bodySkipReason({ ...base, contentType: 'image/png' })).toBe('content-type');
    expect(bodySkipReason({ ...base, contentLength: '5000' })).toBe('too-large');
    expect(
      bodySkipReason({
        ...base,
        resourceType: 'script',
        contentType: 'application/json',
        contentLength: '5000',
      }),
    ).toBeNull();
    expect(typeAllowed('application/problem+json', ['*+json'])).toBe(true);
  });

  test('05-REQ-22 the init script is under 2 KB', () => {
    expect(Buffer.byteLength(cspListenerScript('__pwSec_12345678'))).toBeLessThan(2048);
  });
});
