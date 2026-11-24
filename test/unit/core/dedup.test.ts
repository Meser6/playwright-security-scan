import { describe, expect, test } from 'vitest';
import { dedupeRun, dedupeTest, toFinding } from '../../../src/core/fingerprint/index.ts';
import type { Finding, RawFinding, TestContextRef } from '../../../src/core/types/index.ts';

const ctx = (testId: string, file = 'a.spec.ts', line = 1): TestContextRef => ({
  testId,
  titlePath: [testId],
  file,
  line,
  project: 'chromium',
});

const raw = (over: Partial<RawFinding> = {}): RawFinding => ({
  ruleId: 'header.xcto-missing',
  severity: 'low',
  confidence: 'high',
  scope: 'origin',
  subject: 'https://app.test',
  location: { origin: 'https://app.test' },
  evidence: [{ kind: 'header', name: 'content-type', snippet: 'text/html' }],
  message: 'The response has no X-Content-Type-Options: nosniff.',
  ...over,
});

describe('deduplication (07, chapter 4)', () => {
  test('07-REQ-09 one test: occurrences summed, 3 unique evidence items, first firstSeen', () => {
    const t = ctx('t1');
    const findings = [1, 2, 3, 4, 5].map((n) =>
      toFinding(raw({ evidence: [{ kind: 'header', snippet: `v${n % 4}` }] }), t, 'browser'),
    );
    const [merged, ...rest] = dedupeTest(findings);
    expect(rest).toEqual([]);
    expect(merged?.occurrences).toBe(5);
    expect(merged?.evidence.map((e) => e.snippet)).toEqual(['v1', 'v2', 'v3']);
    expect(merged?.firstSeen).toEqual(t);
    expect(merged?.tests).toEqual(['t1']);
  });

  test('07-REQ-10 run: tests listed, at most 50, independent of the order tests finished', () => {
    const findings: Finding[] = [];
    for (let i = 0; i < 60; i++) {
      findings.push(
        toFinding(raw(), ctx(`t${String(i).padStart(2, '0')}`, 'a.spec.ts', i + 1), 'browser'),
      );
    }
    const forward = dedupeRun(findings);
    const backward = dedupeRun([...findings].reverse());
    expect(forward).toEqual(backward);
    expect(forward[0]?.tests).toHaveLength(50);
    expect(forward[0]?.tests[0]).toBe('t00');
    expect(forward[0]?.firstSeen.testId).toBe('t00');
    expect(forward[0]?.occurrences).toBe(60);
  });

  test('07-REQ-11 the highest severity wins; sources are united (15-REQ-09)', () => {
    const merged = dedupeRun([
      toFinding(raw({ severity: 'low' }), ctx('a'), 'api'),
      toFinding(raw({ severity: 'medium' }), ctx('b'), 'browser'),
    ]);
    expect(merged).toHaveLength(1);
    expect(merged[0]?.severity).toBe('medium');
    expect(merged[0]?.sources).toEqual(['browser', 'api']);
  });

  test('different discriminators stay separate findings', () => {
    const merged = dedupeTest([
      toFinding(raw({ discriminator: 'a' }), ctx('t'), 'browser'),
      toFinding(raw({ discriminator: 'b' }), ctx('t'), 'browser'),
    ]);
    expect(merged.map((f) => f.fingerprint)).toEqual([
      'header.xcto-missing|origin|https://app.test|a',
      'header.xcto-missing|origin|https://app.test|b',
    ]);
  });
});
