// Deduplication of findings (07, chapter 4): within a test in the worker and across the run in
// the reporter.
import {
  confidenceRank,
  severityRank,
  type Finding,
  type RawFinding,
  type Source,
  type TestContextRef,
} from '../types/index.ts';
import { fingerprintOf } from './fingerprint.ts';

/** Evidence kept per finding (07-REQ-09). */
export const MAX_EVIDENCE = 3;
/** Tests listed per finding (07-REQ-10). */
export const MAX_TESTS = 50;

const SOURCE_ORDER: readonly Source[] = ['browser', 'api'];

/** One occurrence of a redacted raw finding in a test, as a finding. */
export function toFinding(raw: RawFinding, context: TestContextRef, source: Source): Finding {
  const finding: Finding = {
    ruleId: raw.ruleId,
    severity: raw.severity,
    confidence: raw.confidence,
    scope: raw.scope,
    subject: raw.subject,
    location: { ...raw.location },
    evidence: raw.evidence.slice(0, MAX_EVIDENCE),
    message: raw.message,
    fingerprint: fingerprintOf(raw),
    occurrences: 1,
    firstSeen: context,
    tests: [context.testId],
    sources: [source],
  };
  if (raw.discriminator !== undefined) finding.discriminator = raw.discriminator;
  return finding;
}

const compareText = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/** Deterministic test order: file, line, title path, project, test id (07-REQ-10, P-06). */
export function compareTests(a: TestContextRef, b: TestContextRef): number {
  return (
    compareText(a.file, b.file) ||
    a.line - b.line ||
    compareText(a.titlePath.join('\u0000'), b.titlePath.join('\u0000')) ||
    compareText(a.project, b.project) ||
    compareText(a.testId, b.testId)
  );
}

const evidenceKey = (e: Finding['evidence'][number]): string =>
  `${e.kind}\u0000${e.name ?? ''}\u0000${e.snippet}`;

function merge(into: Finding, next: Finding): void {
  into.occurrences += next.occurrences;
  // The highest severity and confidence win (07-REQ-11).
  if (severityRank(next.severity) > severityRank(into.severity)) into.severity = next.severity;
  if (confidenceRank(next.confidence) > confidenceRank(into.confidence)) {
    into.confidence = next.confidence;
  }
  const seen = new Set(into.evidence.map(evidenceKey));
  for (const e of next.evidence) {
    if (into.evidence.length >= MAX_EVIDENCE) break;
    if (!seen.has(evidenceKey(e))) {
      seen.add(evidenceKey(e));
      into.evidence.push(e);
    }
  }
  for (const test of next.tests) {
    if (into.tests.length >= MAX_TESTS) break;
    if (!into.tests.includes(test)) into.tests.push(test);
  }
  const sources = new Set([...into.sources, ...next.sources]);
  into.sources = SOURCE_ORDER.filter((s) => sources.has(s));
}

const clone = (f: Finding): Finding => ({
  ...f,
  location: { ...f.location },
  evidence: [...f.evidence],
  tests: [...f.tests],
  sources: [...f.sources],
  firstSeen: { ...f.firstSeen, titlePath: [...f.firstSeen.titlePath] },
});

/**
 * Findings of one test merged by fingerprint in the order they occurred (07-REQ-09): occurrences
 * summed, the first 3 unique evidence items, firstSeen of the first occurrence. Sorted by
 * fingerprint.
 */
export function dedupeTest(findings: readonly Finding[]): Finding[] {
  const byPrint = new Map<string, Finding>();
  for (const finding of findings) {
    const existing = byPrint.get(finding.fingerprint);
    if (existing === undefined) byPrint.set(finding.fingerprint, clone(finding));
    else merge(existing, finding);
  }
  return [...byPrint.values()].sort((a, b) => compareText(a.fingerprint, b.fingerprint));
}

/**
 * Findings of all tests merged by fingerprint (07-REQ-10): the inputs are taken in the
 * deterministic test order of their firstSeen, so the result does not depend on the order in
 * which tests finished (P-06). Tests are listed in that order, at most 50.
 */
export function dedupeRun(findings: readonly Finding[]): Finding[] {
  const ordered = [...findings].sort(
    (a, b) =>
      compareTests(a.firstSeen, b.firstSeen) || compareText(evidenceKeys(a), evidenceKeys(b)),
  );
  return dedupeTest(ordered);
}

const evidenceKeys = (f: Finding): string => f.evidence.map(evidenceKey).join('\u0001');
