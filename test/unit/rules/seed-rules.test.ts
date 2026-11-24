import { describe, expect, test } from 'vitest';
import { resolveConfig } from '../../../src/core/config/index.ts';
import { Redactor } from '../../../src/core/fingerprint/index.ts';
import { BUILT_IN_RULES } from '../../../src/core/rules/index.ts';
import type { BuiltInRule, RuleContext } from '../../../src/core/rules/index.ts';
import type { BrowserEvent, ResponseRecord } from '../../../src/core/types/index.ts';

const cfg = resolveConfig(undefined);
if (!cfg.ok) throw new Error('config');
const rule = (id: string): BuiltInRule => BUILT_IN_RULES.find((r) => r.id === id) as BuiltInRule;
const ctx = (r: BuiltInRule): RuleContext => ({
  options: cfg.config.rules[r.id]?.options ?? {},
  severity: r.manifest.defaultSeverity,
  confidence: r.manifest.defaultConfidence,
  localDev: false,
  isHttps: true,
  inScope: () => true,
  redact: new Redactor({ salt: 's' }),
});
const ref = { testId: 't', titlePath: ['t'], file: 'a.spec.ts', line: 1, project: 'p' };
const rec = (over: Partial<ResponseRecord>): ResponseRecord => ({
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
  responseHeaders: [],
  context: ref,
  ...over,
});

describe('header.xcto-missing', () => {
  const r = rule('header.xcto-missing');
  test('positive: document and JSON without nosniff', () => {
    expect(r.check(rec({}), ctx(r))).toHaveLength(1);
    const json = rec({
      resourceType: 'api',
      source: 'api',
      responseHeaders: [{ name: 'content-type', value: 'application/json' }],
    });
    expect(r.check(json, ctx(r))[0]?.subject).toBe('https://app.test');
  });
  test('negative: nosniff present, images, non-2xx', () => {
    expect(
      r.check(
        rec({ responseHeaders: [{ name: 'x-content-type-options', value: 'NoSniff' }] }),
        ctx(r),
      ),
    ).toEqual([]);
    expect(r.check(rec({ resourceType: 'image' }), ctx(r))).toEqual([]);
    expect(r.check(rec({ status: 404 }), ctx(r))).toEqual([]);
    expect(
      r.check(
        rec({
          resourceType: 'fetch',
          responseHeaders: [{ name: 'content-type', value: 'text/plain' }],
        }),
        ctx(r),
      ),
    ).toEqual([]);
  });
});

describe('data.secret-in-asset', () => {
  const r = rule('data.secret-in-asset');
  const body = (text: string) => ({
    contentType: 'application/javascript',
    text,
    truncated: false,
    sha256: 'x',
  });
  test('positive: AWS key in a bundle, asset subject with the build hash normalized', () => {
    const out = r.check(
      rec({
        resourceType: 'script',
        url: 'https://app.test/main.1a2b3c4d.js',
        body: body('k="AKIAZ7QW3EXAMPLEKEY9"'),
      }),
      ctx(r),
    );
    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({
      scope: 'asset',
      subject: 'https://app.test/main.*.js',
      discriminator: 'aws-access-key',
      confidence: 'high',
    });
    expect(JSON.stringify(out)).not.toContain('AKIAZ7QW3EXAMPLEKEY9');
  });
  test('Google API keys have low confidence; ignore and custom patterns', () => {
    const g = r.check(
      rec({ resourceType: 'script', body: body('AIzaSyA1234567890abcdefghijklmnopqrstuv') }),
      ctx(r),
    );
    expect(g[0]?.confidence).toBe('low');
    const c = ctx(r);
    c.options = {
      ignore: ['google-api-key'],
      patterns: [{ name: 'internal', regex: 'INT-[0-9]{6}' }],
    };
    const out = r.check(
      rec({
        resourceType: 'fetch',
        body: body('AIzaSyA1234567890abcdefghijklmnopqrstuv INT-123456'),
      }),
      c,
    );
    expect(out.map((f) => [f.discriminator, f.scope])).toEqual([['internal', 'endpoint']]);
  });
  test('negative: no body, no secret', () => {
    expect(r.check(rec({ resourceType: 'script' }), ctx(r))).toEqual([]);
    expect(r.check(rec({ resourceType: 'script', body: body('var a = 1;') }), ctx(r))).toEqual([]);
  });
});

describe('data.token-in-storage', () => {
  const r = rule('data.token-in-storage');
  const ev = (entries: { key: string; value: string }[]): BrowserEvent => ({
    kind: 'storage',
    origin: 'https://app.test',
    area: 'local',
    entries,
    context: ref,
  });
  test('positive: a JWT anywhere, a token-like value under a token-ish key', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl';
    const out = r.check(
      ev([
        { key: 'state', value: jwt },
        { key: 'session_8f14e45f', value: 'q8F2kL9xP3mZ7vT1wR5y' },
      ]),
      ctx(r),
    );
    expect(out.map((f) => f.subject)).toEqual([
      'state@https://app.test',
      'session_*@https://app.test',
    ]);
    expect(JSON.stringify(out)).not.toContain(jwt);
  });
  test('negative: plain values', () => {
    expect(
      r.check(
        ev([
          { key: 'theme', value: 'dark' },
          { key: 'token_hint', value: 'short' },
        ]),
        ctx(r),
      ),
    ).toEqual([]);
  });
});
