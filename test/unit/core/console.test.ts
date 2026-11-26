import { describe, expect, test } from 'vitest';
import { emptyCoverage } from '../../../src/core/coverage.ts';
import {
  colorEnabled,
  formatBanner,
  formatBaselineDiff,
  formatSummary,
  MAX_SUMMARY_LINES,
  stripAnsi,
} from '../../../src/core/report/console.ts';
import type { TerminalOptions } from '../../../src/core/report/console.ts';
import type { ClassifiedFinding, Diagnostic, RunReport } from '../../../src/core/types/index.ts';

const ref = {
  testId: 't1',
  titlePath: ['shop', 'login'],
  file: 'tests/login.spec.ts',
  line: 7,
  project: 'chromium',
};

const finding = (i: number, over: Partial<ClassifiedFinding> = {}): ClassifiedFinding => ({
  ruleId: 'cookie.no-httponly',
  severity: 'medium',
  confidence: 'high',
  scope: 'cookie',
  subject: `sid${i}@shop.test`,
  location: { origin: 'https://shop.test' },
  evidence: [],
  message: 'Session cookie is readable by JavaScript.',
  fingerprint: `cookie.no-httponly|cookie|sid${i}@shop.test`,
  occurrences: 1,
  firstSeen: ref,
  tests: ['t1'],
  sources: ['browser'],
  classification: 'new',
  blocking: true,
  ...over,
});

const NAMES = ['OK', 'NEW_FINDINGS', 'BASELINE_EXPIRED', 'TOOL_ERROR', 'NO_TRAFFIC'] as const;

function report(
  findings: ClassifiedFinding[],
  code: RunReport['outcome']['code'],
  diagnostics: Diagnostic[] = [],
): RunReport {
  const coverage = emptyCoverage();
  coverage.responses = 12;
  return {
    schemaVersion: 1,
    runId: 'r1',
    startedAt: '2026-11-25T10:00:00.000Z',
    finishedAt: '2026-11-25T10:01:00.000Z',
    mode: 'scan',
    env: null,
    pkgVersion: '0.1.0',
    playwrightVersion: '1.57.0',
    scope: { origins: ['https://shop.test'] },
    coverage,
    findings,
    resolved: [],
    notCovered: [],
    testsWithoutTraffic: [],
    gate: { minSeverity: 'medium', minConfidence: 'medium', failed: code !== 0, blocking: [] },
    diagnostics,
    outcome: {
      schemaVersion: 1,
      code,
      env: null,
      name: NAMES[code],
      testsPassed: true,
      newBlocking: findings.filter((f) => f.classification === 'new' && f.blocking).length,
      newNonBlocking: findings.filter((f) => f.classification === 'new' && !f.blocking).length,
      expired: findings.filter((f) => f.classification === 'expired').length,
      resolved: 0,
    },
  };
}

const PLAIN: TerminalOptions = { width: 100, color: false, ascii: false };
const COLOR: TerminalOptions = { ...PLAIN, color: true };
const DUMB: TerminalOptions = { ...PLAIN, ascii: true };
const REPORT = '/home/me/shop/reports/pw-sec/report.html';

const warn: Diagnostic = { code: 'LOCAL_ORIGIN', level: 'warn', message: 'a local origin' };
const error: Diagnostic = { code: 'BASELINE_INVALID', level: 'error', message: 'bad file' };

describe('console (04, chapter 4b)', () => {
  test('04-AC-03 colors only add ANSI sequences; TERM=dumb has no emoji and no Unicode frames', () => {
    const r = report([finding(1), finding(2, { classification: 'expired' })], 1, [warn, error]);
    const colored = formatSummary(r, REPORT, COLOR).join('\n');
    const plain = formatSummary(r, REPORT, PLAIN).join('\n');
    expect(colored).toContain('\u001b[');
    expect(plain).not.toContain('\u001b[');
    expect(stripAnsi(colored)).toBe(plain);

    const banner = {
      mode: 'scan' as const,
      scope: ['https://shop.test'],
      enabledRules: 44,
      preset: 'recommended',
      minSeverity: 'medium',
      minConfidence: 'medium',
      baselinePath: 'security-baseline.json',
      baselineEntries: 3,
      reportPath: 'reports/pw-sec/report.html',
      notes: [warn],
    };
    expect(stripAnsi(formatBanner(banner, COLOR).join('\n'))).toBe(
      formatBanner(banner, PLAIN).join('\n'),
    );

    const dumb = [...formatBanner(banner, DUMB), ...formatSummary(r, REPORT, DUMB)].join('\n');
    expect(dumb).not.toMatch(/[─│┌┐└┘├┤┬┴┼╭╮╰╯]/u);
    expect(dumb).not.toMatch(/[✅❌⚠⌛🔒]/u);
    expect(dumb).toContain('FAILED');
  });

  test('04-AC-03 the color decision follows NO_COLOR, FORCE_COLOR and TERM', () => {
    const tty = { isTTY: true };
    const pipe = { isTTY: false };
    expect(colorEnabled(tty, {})).toBe(true);
    expect(colorEnabled(pipe, {})).toBe(false);
    expect(colorEnabled(tty, { TERM: 'dumb' })).toBe(false);
    expect(colorEnabled(pipe, { FORCE_COLOR: '1' })).toBe(true);
    expect(colorEnabled(tty, { FORCE_COLOR: '0' })).toBe(false);
    expect(colorEnabled(pipe, { FORCE_COLOR: '1', NO_COLOR: '1' })).toBe(false);
  });

  test('04-AC-04 40 blocking findings with diagnostics fit in 30 lines with the verdict and the Report line', () => {
    const many = Array.from({ length: 40 }, (_, i) => finding(i));
    const diags = [warn, { ...warn, code: 'W2' }, { ...warn, code: 'W3' }, { ...warn, code: 'W4' }];
    for (const opts of [PLAIN, DUMB, { ...PLAIN, width: 40 }]) {
      const lines = formatSummary(report(many, 1, diags), REPORT, opts);
      expect(lines.length).toBeLessThanOrEqual(MAX_SUMMARY_LINES);
      const text = lines.join('\n');
      expect(text).toContain('FAILED');
      expect(text).toContain('NEW_FINDINGS (code 1)');
      expect(text).toMatch(/… and \d+ more \(see the report\)/);
      expect(lines[lines.length - 1]).toBe(`Report: ${REPORT}`);
    }
  });

  test('04-AC-05 the verdict box matches the result code', () => {
    const verdictOf = (r: RunReport): string => {
      const text = formatSummary(r, REPORT, PLAIN).join('\n');
      return /│ ([✅⚠❌]\s+[A-Z ]+?) {2}/u.exec(text)?.[1] ?? '';
    };
    expect(verdictOf(report([], 0))).toBe('✅  PASSED');
    expect(verdictOf(report([finding(1, { blocking: false })], 0))).toBe('⚠  PASSED WITH WARNINGS');
    expect(verdictOf(report([], 0, [warn]))).toBe('⚠  PASSED WITH WARNINGS');
    expect(verdictOf(report([finding(1)], 1))).toBe('❌  FAILED');
    expect(verdictOf(report([finding(1, { classification: 'expired' })], 2))).toBe('❌  FAILED');
    expect(verdictOf(report([], 3, [error]))).toBe('❌  ERROR');
    expect(verdictOf(report([], 4))).toBe('❌  FAILED');

    const text = (r: RunReport): string => formatSummary(r, REPORT, PLAIN).join('\n');
    expect(text(report([], 0))).toContain('OK (code 0): no new findings ≥ medium');
    expect(text(report([finding(1, { classification: 'expired' })], 2))).toContain(
      'BASELINE_EXPIRED (code 2): 1 expired baseline entry',
    );
    expect(text(report([], 3, [error]))).toContain(
      'TOOL_ERROR (code 3): BASELINE_INVALID; the scan result is not trustworthy',
    );
    expect(text(report([], 4))).toContain('NO_TRAFFIC (code 4): no response in scope');
    expect(text({ ...report([], 0), mode: 'baseline' })).toContain(
      'baseline written (informational, gate disabled)',
    );
  });

  test('04-REQ-09 the baseline diff keeps its text with colors', () => {
    const diff = {
      added: [{ ruleId: 'header.csp-unsafe', subject: 'https://shop.test', severity: 'medium' }],
      removed: [{ ruleId: 'cookie.no-httponly', subject: 'sid@shop.test' }],
      unchanged: 2,
    } as Parameters<typeof formatBaselineDiff>[1];
    const plain = formatBaselineDiff('security-baseline.json', diff, true, PLAIN);
    expect(plain).toEqual([
      'security-baseline.json',
      '  + header.csp-unsafe | https://shop.test   medium',
      '  - cookie.no-httponly | sid@shop.test   (resolved)',
      '  = 2 unchanged',
      '  (partial run: resolved entries were kept)',
      'Review the new entries, add a "note" (and optionally "until"), then commit.',
    ]);
    expect(formatBaselineDiff('security-baseline.json', diff, true, COLOR).map(stripAnsi)).toEqual(
      plain,
    );
  });
});
