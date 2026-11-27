// Run reports for the HTML report tests (09, chapter 3): a big generated run and a small run
// with one finding per baseline state (09-AC-07).
import { emptyCoverage } from '../../src/core/coverage.ts';
import { resolveConfig } from '../../src/core/config/index.ts';
import type { ResolvedSecurityConfig } from '../../src/core/config/index.ts';
import { BUILT_IN_RULES } from '../../src/core/rules/index.ts';
import type { ClassifiedFinding, RunReport, TestContextRef } from '../../src/core/types/index.ts';
import type { HtmlReportInput } from '../../src/html/index.ts';

export function testRef(i: number): TestContextRef {
  return {
    testId: `t${String(i)}`,
    titlePath: ['shop', `test ${String(i)}`],
    file: `tests/area-${String(i % 10)}.spec.ts`,
    line: i + 1,
    project: 'chromium',
  };
}

export function bigFinding(i: number): ClassifiedFinding {
  const rule = BUILT_IN_RULES[i % BUILT_IN_RULES.length] as (typeof BUILT_IN_RULES)[number];
  const blocking = i % 7 === 0;
  return {
    ruleId: rule.id,
    severity: blocking ? 'high' : 'low',
    confidence: 'high',
    scope: 'endpoint',
    subject: `GET /api/items/${String(i)}/details`,
    location: {
      origin: i % 2 === 0 ? 'https://shop.test' : 'https://api.shop.test',
      endpointKey: `GET /api/items/${String(i)}/details`,
    },
    evidence: [
      {
        kind: 'header',
        name: 'x-test',
        snippet: `value ${String(i)} [redacted sha256:1a2b3c] <script>alert(1)</script>`.slice(
          0,
          200,
        ),
      },
      { kind: 'body', snippet: 'x'.repeat(150) },
    ],
    message: `Finding number ${String(i)} on the endpoint.`,
    fingerprint: `${rule.id}|endpoint|GET /api/items/${String(i)}/details`,
    occurrences: 3,
    firstSeen: testRef(i),
    tests: Array.from({ length: 5 }, (_, k) => `t${String(i + k)}`),
    sources: ['browser'],
    classification: blocking ? 'new' : i % 3 === 0 ? 'accepted' : 'new',
    blocking,
    ...(i % 3 === 0 && !blocking
      ? { baseline: { status: 'accepted' as const, note: 'ticket SEC-1', addedAt: '2026-11-01' } }
      : {}),
  };
}

function baseReport(findings: ClassifiedFinding[]): RunReport {
  const coverage = emptyCoverage();
  coverage.responses = 1234;
  coverage.apiResponses = 34;
  coverage.documents = 40;
  coverage.bodiesAnalyzed = 300;
  coverage.bodiesSkipped = { 'too-large': 2 };
  coverage.origins['https://shop.test'] = { responses: 1000, documents: 40 };
  coverage.origins['https://api.shop.test'] = { responses: 234, documents: 0 };
  coverage.endpoints['GET /api/items/:id'] = 12;
  coverage.endpoints['POST /api/orders'] = 3;
  coverage.rulesRun['header.xcto-missing'] = 30;
  const blocking = findings.filter((f) => f.blocking).length;
  const expired = findings.filter((f) => f.classification === 'expired').length;
  return {
    schemaVersion: 2,
    runId: 'r1',
    startedAt: '2026-11-24T20:00:00.000Z',
    finishedAt: '2026-11-24T20:05:00.000Z',
    mode: 'scan',
    shards: null,
    authz: null,
    pkgVersion: '0.2.0',
    playwrightVersion: '1.57.0',
    scope: { origins: ['https://shop.test', 'https://api.shop.test'] },
    coverage,
    findings,
    resolved: [
      {
        fingerprint: 'cookie.no-secure|cookie|old@shop.test',
        ruleId: 'cookie.no-secure',
        subject: 'old@shop.test',
      },
    ],
    notCovered: [],
    testsWithoutTraffic: [
      {
        testId: 'x',
        titlePath: ['no traffic'],
        file: 'tests/x.spec.ts',
        line: 3,
        project: 'chromium',
      },
    ],
    gate: {
      minSeverity: 'medium',
      minConfidence: 'medium',
      failed: blocking > 0,
      blocking: findings.filter((f) => f.blocking).map((f) => f.fingerprint),
    },
    diagnostics: [{ code: 'BODY_READ_FAILED', level: 'info', message: 'one body' }],
    outcome: {
      schemaVersion: 2,
      code: blocking > 0 ? 1 : 0,
      name: blocking > 0 ? 'NEW_FINDINGS' : 'OK',
      mode: 'scan',
      shard: null,
      testsPassed: true,
      newBlocking: blocking,
      newNonBlocking: findings.filter((f) => f.classification === 'new' && !f.blocking).length,
      expired,
      resolved: 1,
    },
  };
}

export const CONFIG: ResolvedSecurityConfig = (() => {
  const resolved = resolveConfig({ baseline: { requireNote: true } });
  if (!resolved.ok) throw new Error('config');
  return resolved.config;
})();

export function bigInput(count: number): HtmlReportInput {
  const findings = Array.from({ length: count }, (_, i) => bigFinding(i));
  return {
    report: baseReport(findings),
    rules: BUILT_IN_RULES,
    config: CONFIG,
    tests: new Map(Array.from({ length: count + 5 }, (_, i) => [`t${String(i)}`, testRef(i)])),
  };
}

/** The baseline states of 09-AC-07, by the name of the golden file. */
export const STATES = [
  'new-blocking',
  'new-non-blocking',
  'accepted',
  'accepted-expiring',
  'wontfix',
  'false-positive',
  'expired',
] as const;
export type State = (typeof STATES)[number];

function stateFinding(state: State, i: number): ClassifiedFinding {
  const base = {
    severity: 'medium' as const,
    confidence: 'high' as const,
    occurrences: 2,
    firstSeen: { ...testRef(i), step: 'open the cart' },
    tests: [`t${String(i)}`, `t${String(i + 1)}`],
    sources: ['browser' as const, 'api' as const],
    evidence: [
      { kind: 'cookie' as const, name: 'sid', snippet: 'sid=[redacted sha256:9f8e7d]; Path=/' },
    ],
  };
  const common = (
    ruleId: string,
    subject: string,
  ): Omit<ClassifiedFinding, 'classification' | 'blocking'> => ({
    ...base,
    ruleId,
    scope: ruleId.startsWith('cookie.') ? 'cookie' : 'origin',
    subject,
    location: { origin: 'https://shop.test' },
    message: `${ruleId} on ${subject} (${state}).`,
    fingerprint: `${ruleId}|${state}|${subject}`,
  });
  switch (state) {
    case 'new-blocking':
      return {
        ...common('cookie.no-secure', 'sid@shop.test'),
        severity: 'high',
        classification: 'new',
        blocking: true,
      };
    case 'new-non-blocking':
      return {
        ...common('header.xcto-missing', 'https://shop.test'),
        severity: 'low',
        classification: 'new',
        blocking: false,
      };
    case 'accepted':
      return {
        ...common('header.hsts-missing', 'https://shop.test'),
        classification: 'accepted',
        blocking: false,
        baseline: {
          status: 'accepted',
          note: 'HSTS is set by the CDN, SEC-12',
          addedAt: '2026-10-01',
          until: '2027-06-30',
        },
      };
    case 'accepted-expiring':
      return {
        ...common('header.csp-missing', 'https://shop.test'),
        classification: 'accepted',
        blocking: false,
        baseline: {
          status: 'accepted',
          note: 'CSP rollout, SEC-20',
          addedAt: '2026-10-01',
          until: '2026-12-01',
          expiresInDays: 7,
        },
      };
    case 'wontfix':
      return {
        ...common('header.clickjacking', 'https://shop.test'),
        classification: 'wontfix',
        blocking: false,
        baseline: { status: 'wontfix', addedAt: '2026-10-02' },
      };
    case 'false-positive':
      return {
        ...common('cookie.no-httponly', 'theme@shop.test'),
        classification: 'false-positive',
        blocking: false,
        baseline: {
          status: 'false-positive',
          note: 'UI theme cookie, read by JavaScript',
          addedAt: '2026-10-03',
        },
      };
    case 'expired':
      return {
        ...common('cookie.samesite-missing', 'cart@shop.test'),
        classification: 'expired',
        blocking: false,
        baseline: {
          status: 'accepted',
          note: 'until the cart rewrite, SEC-7',
          addedAt: '2026-09-01',
          until: '2026-11-20',
        },
      };
  }
}

export function statesInput(): HtmlReportInput {
  const findings = STATES.map((s, i) => stateFinding(s, i));
  const report = baseReport(findings);
  report.outcome = { ...report.outcome, code: 1, name: 'NEW_FINDINGS' };
  report.diagnostics.push({
    code: 'BASELINE_NOTE_MISSING',
    level: 'warn',
    message: 'one entry has no note',
  });
  return {
    report,
    rules: BUILT_IN_RULES,
    config: CONFIG,
    tests: new Map(Array.from({ length: 10 }, (_, i) => [`t${String(i)}`, testRef(i)])),
  };
}
