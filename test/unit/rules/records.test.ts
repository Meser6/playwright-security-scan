// Rule unit tests on records from files (10, chapter 2; 06-REQ-02): every rule has positive and
// negative cases in test/fixtures/records/<ruleId>/{positive,negative}/*.json.
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, test } from 'vitest';
import { applies } from '../../../src/collector/test-collector.ts';
import { resolveConfig } from '../../../src/core/config/index.ts';
import { Redactor } from '../../../src/core/fingerprint/index.ts';
import { createKeyBuilder, resolveNormalization } from '../../../src/core/normalize/index.ts';
import { BUILT_IN_RULES } from '../../../src/core/rules/index.ts';
import type { BuiltInRule, RuleContext } from '../../../src/core/rules/index.ts';
import type {
  BrowserEvent,
  RawFinding,
  ResponseRecord,
  TestTraffic,
} from '../../../src/core/types/index.ts';

const ROOT = join(import.meta.dirname, '../../fixtures/records');
const config = resolveConfig({ rules: { preset: 'strict' } });
if (!config.ok) throw new Error('config');
const keys = createKeyBuilder(resolveNormalization(), { baseOrigins: ['https://app.test'] });
const ref = { testId: 't', titlePath: ['t'], file: 'a.spec.ts', line: 1, project: 'p' };

interface Case {
  title: string;
  input: Record<string, unknown>;
  options?: Record<string, unknown>;
  context?: Partial<RuleContext>;
  expect: Partial<RawFinding>[];
}

/** A request of a test-traffic file with defaults (06-REQ-04: rules on test-traffic files). */
function toTrafficRequest(
  raw: Record<string, unknown>,
  i: number,
): TestTraffic['requests'][number] {
  return {
    id: i + 1,
    method: 'GET',
    endpointKey: 'GET /',
    origin: 'https://app.test',
    status: 200,
    resourceType: 'document',
    isLoginCandidate: false,
    sentCookies: [],
    setCookies: [],
    hasAuthorization: false,
    csrfSignal: false,
    ...raw,
  } as TestTraffic['requests'][number];
}

function toInput(raw: Record<string, unknown>): ResponseRecord | BrowserEvent | TestTraffic {
  if (raw.kind === 'test-end') {
    return {
      kind: 'test-end',
      context: ref,
      requests: ((raw.requests as Record<string, unknown>[] | undefined) ?? []).map(
        toTrafficRequest,
      ),
      jarCookies: (raw.jarCookies as TestTraffic['jarCookies'] | undefined) ?? [],
    };
  }
  if (typeof raw.kind === 'string') return { ...raw, context: ref } as unknown as BrowserEvent;
  const url = (raw.url as string | undefined) ?? 'https://app.test/';
  const method = (raw.method as string | undefined) ?? 'GET';
  const resourceType = (raw.resourceType as string | undefined) ?? 'document';
  const key = keys({ method, url, resourceType });
  const responseHeaders =
    (raw.responseHeaders as ResponseRecord['responseHeaders'] | undefined) ?? [];
  const record: ResponseRecord = {
    kind: 'response',
    id: 1,
    source: 'browser',
    method,
    url,
    endpointKey: key.ok ? key.key : `${method} ${url}`,
    origin: new URL(url).origin,
    resourceType,
    isNavigation: resourceType === 'document',
    requestHeaders: [],
    status: 200,
    responseHeaders,
    context: ref,
    ...(raw as Partial<ResponseRecord>),
  } as ResponseRecord;
  if (typeof raw.body === 'string') {
    const type = responseHeaders.find((h) => h.name === 'content-type')?.value ?? '';
    record.body = {
      contentType: type.split(';')[0] ?? '',
      text: raw.body,
      truncated: false,
      sha256: 'x',
    };
  }
  return record;
}

function run(rule: BuiltInRule, c: Case): RawFinding[] {
  const input = toInput(c.input);
  const resolved = config.ok ? config.config.rules[rule.id] : undefined;
  const ctx: RuleContext = {
    options: { ...(resolved?.options ?? {}), ...(c.options ?? {}) },
    severity: rule.manifest.defaultSeverity,
    confidence: rule.manifest.defaultConfidence,
    localDev: false,
    isHttps: true,
    inScope: (origin) => origin === 'https://app.test' || origin === 'http://app.test',
    redact: new Redactor({ salt: 'salt' }),
    ...(c.context ?? {}),
  };
  if (input.kind === 'test-end') {
    if (rule.appliesTo.testEnd !== true) return [];
  } else if (input.kind === 'response') {
    if (!applies(rule, input) && !(rule.appliesTo.outOfScope ?? false)) return [];
  } else if (rule.appliesTo.events?.includes(input.kind) !== true) {
    return [];
  }
  return rule.check(input, ctx);
}

const ruleDirs = readdirSync(ROOT).sort();

describe('rules on records from files (10-REQ-01)', () => {
  for (const id of ruleDirs) {
    const rule = BUILT_IN_RULES.find((r) => r.id === id);
    for (const kind of ['positive', 'negative'] as const) {
      const dir = join(ROOT, id, kind);
      for (const file of readdirSync(dir).sort()) {
        const c = JSON.parse(readFileSync(join(dir, file), 'utf8')) as Case;
        test(`${id} ${kind}: ${c.title}`, () => {
          expect(rule, `no rule ${id}`).toBeDefined();
          const out = run(rule as BuiltInRule, c);
          expect(out).toHaveLength(c.expect.length);
          c.expect.forEach((partial, i) =>
            expect(out[i]).toMatchObject({ ruleId: id, ...partial }),
          );
          if (kind === 'positive') {
            for (const f of out) {
              expect(f.message.length).toBeGreaterThan(0);
              expect(f.evidence.length).toBeGreaterThan(0);
            }
          }
        });
      }
    }
  }
});

describe('06-AC-03 every rule documents why, how to fix (nginx, Express, Spring) and false positives', () => {
  test.each(BUILT_IN_RULES.map((r) => [r.id, r] as const))('%s', (_id, rule) => {
    expect(rule.docs.title.length).toBeGreaterThan(3);
    expect(rule.docs.why.length).toBeGreaterThan(30);
    expect(rule.docs.falsePositives.length).toBeGreaterThan(5);
    expect(rule.docs.fix).toMatch(/nginx/);
    expect(rule.docs.fix).toMatch(/Express/);
    expect(rule.docs.fix).toMatch(/Spring/);
  });
});

describe('the catalog matches the manifest', () => {
  test('ids are unique and each rule has its manifest entry', () => {
    const ids = BUILT_IN_RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const rule of BUILT_IN_RULES) expect(rule.manifest.id).toBe(rule.id);
  });
});
