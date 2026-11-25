// Console texts of the reporter (04, chapters 3, 4 and 4b; 08-REQ-09). Pure: the caller passes
// the terminal width, the color decision and TERM=dumb (04-REQ-05). Frames, tables and colors
// follow the perf package; without colors the text is the same apart from the ANSI sequences.
import type { BaselineDiff } from '../baseline/index.ts';
import type { ClassifiedFinding, Diagnostic, RunReport, TestContextRef } from '../types/index.ts';
import { confidenceRank, severityRank } from '../types/index.ts';
import { boxLines, marks, table } from './term/box.ts';
import type { BoxLine, Marks, TableColumn, TableRow } from './term/box.ts';
import { painter } from './term/color.ts';
import type { ColorStyle, Painter } from './term/color.ts';
import { plural, textWidth } from './term/text.ts';

export { colorEnabled, stripAnsi } from './term/color.ts';
export { asciiTerminal } from './term/box.ts';

/** Maximum lines of the summary, from the separator to the Report line (04-REQ-04, 04-REQ-07). */
export const MAX_SUMMARY_LINES = 30;
/** Entries per error or warning box (04-REQ-07). */
export const MAX_BOX_ENTRIES = 3;
/** Terminal columns without a terminal (04-REQ-05). */
export const DEFAULT_WIDTH = 120;

export const PACKAGE_NAME = 'playwright-security-scan';

/** Layout of the console output (04-REQ-05). */
export interface TerminalOptions {
  width: number;
  color: boolean;
  /** TERM=dumb: ASCII frames and text marks instead of emoji. */
  ascii: boolean;
}

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

/** The box of errors (red) or warnings (yellow) with the count in the title (04-REQ-07). */
function issueBox(
  level: 'error' | 'warn',
  issues: readonly Diagnostic[],
  limit: number,
  opts: TerminalOptions,
): string[] {
  if (issues.length === 0) return [];
  const m = marks(opts.ascii);
  const [mark, style, name]: [string, ColorStyle, string] =
    level === 'error' ? [m.error, 'red', 'Errors'] : [m.warn, 'yellow', 'Warnings'];
  const indent = textWidth(mark) + 1;
  const lines: BoxLine[] = issues.slice(0, limit).map((d) => ({
    spans: [{ text: `${mark} ${d.code}`, style }, { text: `: ${d.message}` }],
    indent,
  }));
  if (issues.length > limit) {
    lines.push({ text: `… and ${issues.length - limit} more (see the report)`, style: 'dim' });
  }
  return boxLines(lines, {
    ...opts,
    border: style,
    title: `${opts.ascii ? '' : `${mark} `}${name} (${issues.length})`,
    wrap: true,
  });
}

/** The start banner (04, chapter 3; 04-REQ-06), one string per line. */
export function formatBanner(b: BannerInput, opts: TerminalOptions): string[] {
  const rows: [string, string][] = [
    ['Mode', `${b.mode} · passive only`],
    [
      'Scope',
      b.scope.length === 0 ? '(none: set use.baseURL or scope.origins)' : b.scope.join(', '),
    ],
    ['Rules', `${b.enabledRules} enabled (preset ${b.preset})`],
    [
      'Gate',
      b.mode === 'baseline'
        ? 'off (baseline run)'
        : `new findings ≥ ${b.minSeverity} (confidence ≥ ${b.minConfidence})`,
    ],
    [
      'Baseline',
      `${b.baselinePath} (${b.baselineEntries === null ? 'not found' : plural(b.baselineEntries, 'entry', 'entries')})`,
    ],
    ['Report', b.reportPath],
  ];
  const icon = opts.ascii ? '' : '🔒 ';
  const lines = table(
    [
      { header: '', style: 'bold' },
      { header: '', flex: true, minWidth: 10 },
    ],
    rows.map((cells) => ({ cells })),
    { ...opts, border: 'cyan', header: false, title: `${icon}${PACKAGE_NAME} · ${b.mode} run` },
  );
  const paint = painter(opts.color);
  return [
    ...lines,
    ...issueBox(
      'error',
      b.notes.filter((n) => n.level === 'error'),
      Infinity,
      opts,
    ),
    ...issueBox(
      'warn',
      b.notes.filter((n) => n.level === 'warn'),
      Infinity,
      opts,
    ),
    ...b.notes.filter((n) => n.level === 'info').map((n) => paint(`note: ${n.message}`, 'dim')),
  ];
}

export const testLabel = (t: TestContextRef): string =>
  `${t.file}:${t.line} › ${t.titlePath.join(' › ')}`;

const findingOrder = (a: ClassifiedFinding, b: ClassifiedFinding): number =>
  severityRank(b.severity) - severityRank(a.severity) ||
  confidenceRank(b.confidence) - confidenceRank(a.confidence) ||
  b.tests.length - a.tests.length ||
  (a.fingerprint < b.fingerprint ? -1 : 1);

const isExpiring = (f: ClassifiedFinding): boolean =>
  f.baseline?.expiresInDays !== undefined && f.classification !== 'expired';

type Verdict = [mark: string, word: string, color: ColorStyle, badge: ColorStyle, reason: string];

/** The verdict (04-REQ-08): mark, word, colors and the sentence. */
export function verdict(report: RunReport, m: Marks): Verdict {
  const o = report.outcome;
  const head = `${o.name} (code ${o.code})`;
  const gate = `≥ ${report.gate.minSeverity}`;
  const failed = (reason: string): Verdict => [m.error, 'FAILED', 'red', 'badge-red', reason];
  switch (o.code) {
    case 1:
      return failed(`${head}: ${plural(o.newBlocking, 'new blocking finding')} ${gate}`);
    case 2:
      return failed(
        `${head}: ${plural(o.expired, 'expired baseline entry', 'expired baseline entries')}`,
      );
    case 4:
      return failed(`${head}: no response in scope (gate.failOnNoTraffic)`);
    case 3: {
      const codes = [
        ...new Set(report.diagnostics.filter((d) => d.level === 'error').map((d) => d.code)),
      ];
      return [
        m.error,
        'ERROR',
        'magenta',
        'badge-magenta',
        `${head}: ${codes.join(', ')}; the scan result is not trustworthy`,
      ];
    }
    default: {
      const warnings: string[] = [];
      if (o.newNonBlocking > 0) warnings.push(plural(o.newNonBlocking, 'new non-blocking finding'));
      const expiring = report.findings.filter(isExpiring).length;
      if (expiring > 0) {
        warnings.push(
          expiring === 1
            ? '1 baseline entry expires soon'
            : `${expiring} baseline entries expire soon`,
        );
      }
      const warns = report.diagnostics.filter((d) => d.level === 'warn').length;
      if (warns > 0) warnings.push(plural(warns, 'warning'));
      const base =
        report.mode === 'baseline'
          ? 'baseline written (informational, gate disabled)'
          : `no new findings ${gate}`;
      if (warnings.length === 0)
        return [m.ok, 'PASSED', 'green', 'badge-green', `${head}: ${base}`];
      return [
        m.warn,
        'PASSED WITH WARNINGS',
        'yellow',
        'badge-yellow',
        `${head}: ${base}; ${warnings.join(', ')}`,
      ];
    }
  }
}

/** One-line verdict box: `<mark> <badge> <reason>` (04-REQ-08). */
function verdictBox(report: RunReport, opts: TerminalOptions): string[] {
  const [mark, word, color, badge, reason] = verdict(report, marks(opts.ascii));
  return boxLines(
    [
      {
        spans: [{ text: `${mark} ` }, { text: ` ${word} `, style: badge }, { text: ` ${reason}` }],
        indent: textWidth(mark) + word.length + 4,
      },
    ],
    { ...opts, border: color, wrap: true },
  );
}

function counterLines(report: RunReport, opts: TerminalOptions): string[] {
  const count = (cls: ClassifiedFinding['classification'], blocking?: boolean): number =>
    report.findings.filter(
      (f) => f.classification === cls && (blocking === undefined || f.blocking === blocking),
    ).length;
  const blocking = count('new', true);
  const expired = count('expired');
  const rows: TableRow[] = [
    {
      cells: ['New', `${blocking} blocking · ${count('new', false)} non-blocking`],
      ...(blocking > 0 ? { cellStyles: [undefined, 'red'] } : {}),
    },
    {
      cells: [
        'Baseline',
        `${count('accepted')} accepted · ${count('wontfix')} wontfix · ${count('false-positive')} false-positive · ${expired} expired`,
      ],
      ...(expired > 0 ? { cellStyles: [undefined, 'yellow'] } : {}),
    },
    {
      cells: [
        'Resolved',
        `${report.resolved.length}${report.notCovered.length > 0 ? ` · not covered ${report.notCovered.length}` : ''}`,
      ],
    },
  ];
  return table(
    [
      { header: '', style: 'bold' },
      { header: '', flex: true, minWidth: 10 },
    ],
    rows,
    { ...opts, header: false },
  );
}

/** Table of blocking and expired findings in at most `budget` lines (04-REQ-07, item 5). */
function findingLines(
  important: readonly ClassifiedFinding[],
  budget: number,
  opts: TerminalOptions,
  paint: Painter,
): string[] {
  if (important.length === 0) return [];
  const m = marks(opts.ascii);
  // Frame: top, header, separator, bottom; one more line when rows are left out.
  const fits = important.length + 4 <= budget ? important.length : Math.max(0, budget - 5);
  if (fits === 0) {
    return [
      paint(
        `${m.error} ${plural(important.length, 'blocking or expired finding')} (see the report)`,
        'red',
      ),
    ];
  }
  const columns: TableColumn[] = [
    { header: '' },
    { header: 'rule' },
    { header: 'severity' },
    { header: 'subject', flex: true, minWidth: 20 },
    { header: 'first seen' },
  ];
  const rows: TableRow[] = important.slice(0, fits).map((f) => {
    const expired = f.classification === 'expired';
    return {
      cells: [
        expired ? (opts.ascii ? '!' : '⌛') : m.error,
        f.ruleId,
        `${f.severity}/${f.confidence}`,
        `${f.subject}${f.discriminator === undefined ? '' : ` (${f.discriminator})`}`,
        `${f.firstSeen.file}:${f.firstSeen.line}`,
      ],
      style: expired ? 'yellow' : 'red',
    };
  });
  const lines = table(columns, rows, opts);
  if (fits < important.length) {
    lines.push(paint(`  … and ${important.length - fits} more (see the report)`, 'dim'));
  }
  return lines;
}

function hintLines(report: RunReport, paint: Painter): string[] {
  const lines: string[] = [];
  const n = report.resolved.length;
  if (n > 0 && report.mode === 'scan') {
    lines.push(
      paint(
        `→ ${plural(n, 'baseline entry', 'baseline entries')} resolved — run baseline mode to remove ${n === 1 ? 'it' : 'them'}`,
        'dim',
      ),
    );
  }
  for (const f of report.findings.filter(isExpiring).slice(0, 3)) {
    lines.push(
      paint(
        `! ${f.ruleId} ${f.subject}: baseline entry expires in ${f.baseline?.expiresInDays} days`,
        'yellow',
      ),
    );
  }
  if (report.mode === 'scan' && report.outcome.newBlocking > 0) {
    lines.push(
      `${paint('Next:', 'bold')} ${paint('PW_SEC_MODE=baseline npx playwright test', 'cyan')}   ${paint('(review the diff before commit)', 'dim')}`,
    );
  }
  return lines;
}

/**
 * The end summary (04, chapter 4; 04-REQ-07), at most 30 lines (04-REQ-04). `reportPath` is the
 * absolute path of report.html, or of report.json without HTML, or null when none was written.
 */
export function formatSummary(
  report: RunReport,
  reportPath: string | null,
  opts: TerminalOptions,
): string[] {
  const paint = painter(opts.color);
  const c = report.coverage;
  const head = [
    paint((opts.ascii ? '-' : '─').repeat(Math.max(1, opts.width)), 'dim'),
    paint(
      [
        PACKAGE_NAME,
        `mode: ${report.mode}`,
        `${c.responses} responses in scope${c.apiResponses > 0 ? ` (${c.apiResponses} API)` : ''}`,
        plural(Object.keys(c.endpoints).length, 'endpoint'),
        plural(c.documents, 'document'),
      ].join(' · '),
      'bold',
    ),
    '',
  ];
  const errors = report.diagnostics.filter((d) => d.level === 'error');
  const warns = report.diagnostics.filter((d) => d.level === 'warn');
  const issues = [
    ...issueBox('error', errors, MAX_BOX_ENTRIES, opts),
    ...issueBox('warn', warns, MAX_BOX_ENTRIES, opts),
  ];
  const counters = [...counterLines(report, opts), ''];
  const hints = hintLines(report, paint);
  const tail = [
    ...(hints.length > 0 ? [...hints, ''] : []),
    ...verdictBox(report, opts),
    ...(reportPath === null ? [] : [`${paint('Report:', 'bold')} ${reportPath}`]),
  ];
  const important = report.findings
    .filter((f) => f.blocking || f.classification === 'expired')
    .sort(findingOrder);
  // The issue boxes give way only when not even the one-line findings counter fits (04-REQ-04).
  const fixed = head.length + issues.length + counters.length + tail.length;
  const shownIssues = fixed + 2 > MAX_SUMMARY_LINES ? [] : issues;
  const budget =
    MAX_SUMMARY_LINES - (head.length + shownIssues.length + counters.length + tail.length) - 1;
  const findings = findingLines(important, budget, opts, paint);
  return [
    ...head,
    ...shownIssues,
    ...counters,
    ...(findings.length > 0 ? [...findings, ''] : []),
    ...tail,
  ].slice(0, MAX_SUMMARY_LINES);
}

/** The diff of a baseline run (08-REQ-09, 04-REQ-09). */
export function formatBaselineDiff(
  path: string,
  diff: BaselineDiff,
  partial: boolean,
  opts: TerminalOptions,
): string[] {
  const paint = painter(opts.color);
  const lines = [paint(path, 'bold')];
  for (const a of diff.added.slice(0, 20))
    lines.push(paint(`  + ${a.ruleId} | ${a.subject}   ${a.severity}`, 'yellow'));
  if (diff.added.length > 20) lines.push(paint(`  + … ${diff.added.length - 20} more`, 'yellow'));
  for (const r of diff.removed.slice(0, 20))
    lines.push(paint(`  - ${r.ruleId} | ${r.subject}   (resolved)`, 'green'));
  if (diff.removed.length > 20)
    lines.push(paint(`  - … ${diff.removed.length - 20} more`, 'green'));
  lines.push(paint(`  = ${diff.unchanged} unchanged`, 'dim'));
  if (partial) lines.push(paint('  (partial run: resolved entries were kept)', 'dim'));
  lines.push(
    paint('Review the new entries, add a "note" (and optionally "until"), then commit.', 'bold'),
  );
  return lines;
}
