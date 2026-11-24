// Console texts of the reporter (04, chapters 3 and 4; 08-REQ-09). Pure.
import type { BaselineDiff } from '../baseline/index.ts';
import type { ClassifiedFinding, Diagnostic, RunReport, TestContextRef } from '../types/index.ts';
import { confidenceRank, severityRank } from '../types/index.ts';

/** Maximum lines of the summary (04-REQ-04). */
export const MAX_SUMMARY_LINES = 30;

export interface BannerInput {
  mode: 'scan' | 'baseline';
  scope: string[];
  enabledRules: number;
  preset: string;
  minSeverity: string;
  minConfidence: string;
  baselinePath: string;
  baselineEntries: number | null;
  reportPath: string;
  notes: Diagnostic[];
}

/** The start banner (04, chapter 3). */
export function formatBanner(b: BannerInput): string[] {
  const lines = [
    `pw-sec · mode: ${b.mode} · passive only`,
    `scope: ${b.scope.length === 0 ? '(none: set use.baseURL or scope.origins)' : b.scope.join(', ')}`,
    `rules: ${b.enabledRules} enabled (preset ${b.preset}) · gate: ${b.mode === 'baseline' ? 'off (baseline run)' : `new findings ≥ ${b.minSeverity} (confidence ≥ ${b.minConfidence})`}`,
    `baseline: ${b.baselinePath} (${b.baselineEntries === null ? 'not found' : `${b.baselineEntries} entries`})`,
    `report: ${b.reportPath}`,
  ];
  for (const n of b.notes) lines.push(`${n.level === 'info' ? 'note' : n.level}: ${n.message}`);
  return lines;
}

export const testLabel = (t: TestContextRef): string =>
  `${t.file}:${t.line} › ${t.titlePath.join(' › ')}`;

const findingOrder = (a: ClassifiedFinding, b: ClassifiedFinding): number =>
  severityRank(b.severity) - severityRank(a.severity) ||
  confidenceRank(b.confidence) - confidenceRank(a.confidence) ||
  b.tests.length - a.tests.length ||
  (a.fingerprint < b.fingerprint ? -1 : 1);

const findingLine = (f: ClassifiedFinding, mark: string): string[] => [
  `${mark} ${f.ruleId}   ${f.severity}/${f.confidence}  ${f.subject}${f.discriminator === undefined ? '' : ` (${f.discriminator})`}`,
  `    first seen: ${testLabel(f.firstSeen)}`,
];

/** The end summary (04, chapter 4), at most 30 lines (04-REQ-04). */
export function formatSummary(
  report: RunReport,
  paths: { html: string | null; json: string | null },
): string[] {
  const c = report.coverage;
  const count = (cls: ClassifiedFinding['classification'], blocking?: boolean): number =>
    report.findings.filter(
      (f) => f.classification === cls && (blocking === undefined || f.blocking === blocking),
    ).length;
  const head = [
    `pw-sec · ${c.responses} responses in scope${c.apiResponses > 0 ? ` (${c.apiResponses} API)` : ''} · ${Object.keys(c.endpoints).length} endpoints · ${c.documents} documents`,
    `  NEW       ${count('new', true)} blocking   ${count('new', false)} non-blocking`,
    `  baseline  ${count('accepted')} accepted   ${count('wontfix')} wontfix   ${count('false-positive')} false-positive   ${count('expired')} expired`,
    `  resolved  ${report.resolved.length}${report.notCovered.length > 0 ? `   not covered ${report.notCovered.length}` : ''}`,
  ];
  const tail: string[] = [];
  if (report.resolved.length > 0 && report.mode === 'scan') {
    tail.push(
      `→ ${report.resolved.length} baseline ${report.resolved.length === 1 ? 'entry' : 'entries'} resolved — run baseline mode to remove ${report.resolved.length === 1 ? 'it' : 'them'}`,
    );
  }
  const expiring = report.findings.filter(
    (f) => f.baseline?.expiresInDays !== undefined && f.classification !== 'expired',
  );
  for (const f of expiring.slice(0, 3)) {
    tail.push(
      `! ${f.ruleId} ${f.subject}: baseline entry expires in ${f.baseline?.expiresInDays} days`,
    );
  }
  for (const d of report.diagnostics.filter((x) => x.level !== 'info').slice(0, 3)) {
    tail.push(`${d.level === 'error' ? '✘' : '!'} ${d.code}: ${d.message}`);
  }
  if (report.mode === 'scan' && count('new', true) > 0) {
    tail.push(
      '→ accept: PW_SEC_MODE=baseline npx playwright test   (review the diff before commit)',
    );
  }
  if (paths.html !== null) tail.push(`→ report: ${paths.html}`);
  else if (paths.json !== null) tail.push(`→ report: ${paths.json}`);
  tail.push(
    `${report.outcome.code === 0 ? '✔' : '✘'} pw-sec: ${report.outcome.name} (code ${report.outcome.code})`,
  );

  const important = report.findings
    .filter((f) => f.blocking || f.classification === 'expired')
    .sort(findingOrder);
  const budget = MAX_SUMMARY_LINES - head.length - tail.length;
  const body: string[] = [];
  let shown = 0;
  for (const f of important) {
    if (body.length + 2 > budget - 1) break;
    body.push(...findingLine(f, f.classification === 'expired' ? '⌛' : '✘'));
    shown += 1;
  }
  if (shown < important.length)
    body.push(`  … and ${important.length - shown} more (see the report)`);
  return [...head, ...body, ...tail];
}

/** The diff of a baseline run (08-REQ-09). */
export function formatBaselineDiff(path: string, diff: BaselineDiff, partial: boolean): string[] {
  const lines = [path];
  for (const a of diff.added.slice(0, 20))
    lines.push(`  + ${a.ruleId} | ${a.subject}   ${a.severity}`);
  if (diff.added.length > 20) lines.push(`  + … ${diff.added.length - 20} more`);
  for (const r of diff.removed.slice(0, 20))
    lines.push(`  - ${r.ruleId} | ${r.subject}   (resolved)`);
  if (diff.removed.length > 20) lines.push(`  - … ${diff.removed.length - 20} more`);
  lines.push(`  = ${diff.unchanged} unchanged`);
  if (partial) lines.push('  (partial run: resolved entries were kept)');
  lines.push('Review the new entries, add a "note" (and optionally "until"), then commit.');
  return lines;
}
