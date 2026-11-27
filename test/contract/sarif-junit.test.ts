import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Ajv } from 'ajv';
import { describe, expect, test } from 'vitest';
import { emptyCoverage } from '../../src/core/coverage.ts';
import { sha256 } from '../../src/core/hash/index.ts';
import { buildJunit, xml } from '../../src/core/report/junit.ts';
import { buildSarif } from '../../src/core/report/sarif.ts';
import { BUILT_IN_RULES } from '../../src/core/rules/index.ts';
import type { ClassifiedFinding, RunReport } from '../../src/core/types/index.ts';

/** The official schema is draft-04: read it as draft-07 (no draft-04-only keywords are used). */
function sarifValidator() {
  const schema = JSON.parse(
    readFileSync(join(import.meta.dirname, 'vendor/sarif-schema-2.1.0.json'), 'utf8'),
  ) as Record<string, unknown>;
  delete schema.$schema;
  schema.$id = schema.id;
  delete schema.id;
  return new Ajv({ strict: false, validateFormats: false, allErrors: true }).compile(schema);
}

const ref = {
  testId: 't1',
  titlePath: ['shop', 'login'],
  file: 'tests/login.spec.ts',
  line: 7,
  project: 'chromium',
};
const base = (over: Partial<ClassifiedFinding>): ClassifiedFinding => ({
  ruleId: 'cookie.no-httponly',
  severity: 'medium',
  confidence: 'high',
  scope: 'cookie',
  subject: 'sid@shop.test',
  location: { origin: 'https://shop.test', endpointKey: 'POST /api/login' },
  evidence: [{ kind: 'cookie', name: 'sid', snippet: 'sid=[redacted sha256:1a2b3c]; Path=/ <&>"' }],
  message: 'Session cookie sid is readable by JavaScript (no HttpOnly).',
  fingerprint: 'cookie.no-httponly|cookie|sid@shop.test',
  occurrences: 3,
  firstSeen: ref,
  tests: ['t1', 't2'],
  sources: ['browser', 'api'],
  classification: 'new',
  blocking: true,
  ...over,
});

function report(findings: ClassifiedFinding[], code: RunReport['outcome']['code'] = 1): RunReport {
  return {
    schemaVersion: 2,
    runId: 'r1',
    startedAt: '2026-11-24T20:00:00.000Z',
    finishedAt: '2026-11-24T20:01:00.000Z',
    mode: 'scan',
    shards: null,
    authz: null,
    pkgVersion: '0.1.0',
    playwrightVersion: '1.57.0',
    scope: { origins: ['https://shop.test'] },
    coverage: emptyCoverage(),
    findings,
    resolved: [],
    notCovered: [],
    testsWithoutTraffic: [],
    gate: { minSeverity: 'medium', minConfidence: 'medium', failed: true, blocking: [] },
    diagnostics:
      code === 3 ? [{ code: 'BASELINE_INVALID', level: 'error', message: 'bad <file>' }] : [],
    outcome: {
      schemaVersion: 2,
      code,
      name: ['OK', 'NEW_FINDINGS', 'BASELINE_EXPIRED', 'TOOL_ERROR', 'NO_TRAFFIC'][
        code
      ] as RunReport['outcome']['name'],
      mode: 'scan',
      shard: null,
      testsPassed: true,
      newBlocking: 1,
      newNonBlocking: 0,
      expired: 0,
      resolved: 0,
    },
  };
}

const accepted = base({
  ruleId: 'header.csp-unsafe',
  scope: 'origin',
  subject: 'https://shop.test',
  fingerprint: 'header.csp-unsafe|origin|https://shop.test|unsafe-inline',
  discriminator: 'unsafe-inline',
  classification: 'accepted',
  blocking: false,
  baseline: { status: 'accepted', note: 'legacy widget, SEC-12', addedAt: '2026-11-01' },
});
const expired = base({
  ruleId: 'disclosure.server-version',
  severity: 'low',
  scope: 'origin',
  subject: 'https://shop.test',
  fingerprint: 'disclosure.server-version|origin|https://shop.test|server',
  classification: 'expired',
  blocking: true,
  baseline: { status: 'accepted', until: '2026-11-01', addedAt: '2026-10-01' },
});

describe('SARIF 2.1.0 (09, chapter 5)', () => {
  const validate = sarifValidator();

  test('09-AC-01 the log passes the SARIF 2.1.0 schema (the upload to GitHub is checked by hand)', () => {
    const log = buildSarif(report([base({}), accepted, expired]), BUILT_IN_RULES, {
      version: '0.1.0',
      includeAccepted: true,
    });
    expect(validate(log), JSON.stringify(validate.errors)).toBe(true);
    const empty = buildSarif(report([], 0), BUILT_IN_RULES, {
      version: '0.1.0',
      includeAccepted: false,
    });
    expect(validate(empty)).toBe(true);
  });

  test('09-REQ-06 rules carry help, tags with CWE and OWASP, and security-severity', () => {
    const log = buildSarif(report([]), BUILT_IN_RULES, {
      version: '0.1.0',
      includeAccepted: false,
    }) as { runs: { tool: { driver: { name: string; rules: Record<string, unknown>[] } } }[] };
    const driver = log.runs[0]?.tool.driver;
    expect(driver?.name).toBe('playwright-security-scan');
    expect(driver?.rules).toHaveLength(BUILT_IN_RULES.length);
    const rule = driver?.rules.find((r) => r.id === 'cookie.no-httponly');
    expect(rule).toMatchObject({
      properties: { tags: ['security', 'CWE-1004', 'OWASP-A02:2025'], 'security-severity': '5.5' },
      helpUri:
        'https://github.com/Meser6/playwright-security-scan/blob/main/docs/rules/cookie.no-httponly.md',
    });
    expect((rule?.help as { markdown: string }).markdown).toContain('**Fix.**');
  });

  test('09-REQ-07 … 09-REQ-09 test location, stable fingerprint, only new and expired unless asked', () => {
    const log = buildSarif(report([base({}), accepted, expired]), BUILT_IN_RULES, {
      version: '0.1.0',
      includeAccepted: false,
    }) as { runs: { results: Record<string, unknown>[] }[] };
    const results = log.runs[0]?.results ?? [];
    expect(results.map((r) => r.ruleId)).toEqual([
      'cookie.no-httponly',
      'disclosure.server-version',
    ]);
    expect(results[0]).toMatchObject({
      level: 'warning',
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: 'tests/login.spec.ts' },
            region: { startLine: 7 },
          },
        },
      ],
      partialFingerprints: {
        primaryLocationLineHash: sha256('cookie.no-httponly|cookie|sid@shop.test'),
      },
    });
    expect((results[0]?.message as { text: string }).text).toContain('POST /api/login');
    const all = buildSarif(report([accepted]), BUILT_IN_RULES, {
      version: '0.1.0',
      includeAccepted: true,
    }) as { runs: { results: Record<string, unknown>[] }[] };
    expect(all.runs[0]?.results[0]?.suppressions).toEqual([
      { kind: 'external', justification: 'legacy widget, SEC-12' },
    ]);
  });
});

/** Well-formedness: every opened element is closed in order. */
function wellFormed(text: string): boolean {
  const stack: string[] = [];
  for (const m of text.replace(/<\?xml[^>]*\?>/, '').matchAll(/<(\/?)([A-Za-z-]+)[^>]*?(\/?)>/g)) {
    const [, close, name, self] = m;
    if (self === '/') continue;
    if (close === '/') {
      if (stack.pop() !== name) return false;
    } else stack.push(name ?? '');
  }
  return stack.length === 0;
}

describe('JUnit XML (09, chapter 6)', () => {
  test('09-AC-04 (automatic part) well-formed XML in the Surefire shape: suites per group, cases per finding', () => {
    const text = buildJunit(report([base({}), accepted, expired]), BUILT_IN_RULES, {
      includeAccepted: true,
      failOnExpired: true,
    });
    expect(wellFormed(text)).toBe(true);
    expect(text).toMatch(
      /^<\?xml version="1.0" encoding="UTF-8"\?>\n<testsuites name="pw-sec" tests="3" failures="2" errors="0" skipped="1"/,
    );
    expect(text).toContain('<testsuite name="cookie" tests="1" failures="1"');
    expect(text).toContain(
      'classname="pw-sec.cookie.cookie.no-httponly" name="sid@shop.test" file="tests/login.spec.ts" line="7" time="0"',
    );
    expect(text).toContain(
      '<failure type="cookie.no-httponly" message="medium/high: Session cookie sid',
    );
    expect(text).toContain('<failure type="baseline-expired"');
    expect(text).toContain('<skipped message="baseline: accepted; legacy widget, SEC-12"/>');
    expect(text).toContain('&lt;&amp;&gt;&quot;');
  });

  test('09-REQ-10 non-blocking new findings pass with system-out; accepted ones can be left out', () => {
    const text = buildJunit(report([base({ blocking: false }), accepted]), BUILT_IN_RULES, {
      includeAccepted: false,
      failOnExpired: true,
    });
    expect(text).toContain('<system-out>');
    expect(text).not.toContain('<skipped');
    expect(text).toContain('tests="1" failures="0"');
  });

  test('09-REQ-13 an empty run has one passed case; a tool error has an error case', () => {
    expect(
      buildJunit(report([], 0), BUILT_IN_RULES, { includeAccepted: true, failOnExpired: true }),
    ).toContain('<testcase classname="pw-sec" name="no findings" time="0"/>');
    const tool = buildJunit(report([], 3), BUILT_IN_RULES, {
      includeAccepted: true,
      failOnExpired: true,
    });
    expect(tool).toContain('<error type="TOOL_ERROR"');
    expect(tool).toContain('BASELINE_INVALID: bad &lt;file&gt;');
    expect(wellFormed(tool)).toBe(true);
  });

  test('xml() drops characters XML does not allow', () => {
    expect(xml('a\u0001b\u0008c<')).toBe('abc&lt;');
  });
});
