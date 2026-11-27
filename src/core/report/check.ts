// Output of a check (04, chapter 4c; 04-REQ-12): what the scan would see, in the look of 04-REQ-05.
// Pure: the reporter collects the data.
import type { Diagnostic } from '../types/index.ts';
import { boxLines, marks, table } from './term/box.ts';
import type { BoxLine, TableRow } from './term/box.ts';
import { painter } from './term/color.ts';
import type { ColorStyle } from './term/color.ts';
import { plural, textWidth } from './term/text.ts';
import { PACKAGE_NAME } from './console.ts';
import type { TerminalOptions } from './console.ts';

/** Out-of-scope origins listed (04-REQ-12, item 4). */
export const MAX_OUT_OF_SCOPE = 5;

export interface CheckOrigin {
  origin: string;
  source: 'baseURL' | 'scope.origins';
  responses: number;
  documents: number;
}

export interface CheckInput {
  tests: { ran: number; selected: number; passed: number; failed: number; skipped: number };
  maxTests: number;
  origins: CheckOrigin[];
  /** Origin outside the scope → responses. */
  outOfScope: Record<string, number>;
  responses: number;
  apiResponses: number;
  testsWithApi: number;
  projects: string[];
  enabledRules: number;
  /** Enabled custom rules among them (16-REQ-12). */
  customRules?: number;
  preset: string;
  /** `<file> (N entries)`, `<file> (not found)` or `<file> (invalid: CODE)`. */
  baseline: string;
  findings: number;
  newAboveGate: number;
  minSeverity: string;
  diagnostics: Diagnostic[];
}

function issueBox(level: 'error' | 'warn', list: Diagnostic[], opts: TerminalOptions): string[] {
  if (list.length === 0) return [];
  const m = marks(opts.ascii);
  const [mark, style, name]: [string, ColorStyle, string] =
    level === 'error' ? [m.error, 'red', 'Errors'] : [m.warn, 'yellow', 'Warnings'];
  const indent = textWidth(mark) + 1;
  const lines: BoxLine[] = list.map((d) => ({
    spans: [{ text: `${mark} ${d.code}`, style }, { text: `: ${d.message}` }],
    indent,
  }));
  return [
    ...boxLines(lines, {
      ...opts,
      border: style,
      title: `${opts.ascii ? '' : `${mark} `}${name} (${list.length})`,
      wrap: true,
    }),
    '',
  ];
}

/** The check output, one string per line (04-REQ-12). */
export function formatCheck(c: CheckInput, opts: TerminalOptions): string[] {
  const paint = painter(opts.color);
  const m = marks(opts.ascii);
  const t = c.tests;
  const failed = t.failed > 0 ? `, ${t.failed} failed` : '';
  const lines: string[] = [
    paint((opts.ascii ? '-' : '─').repeat(Math.max(1, opts.width)), 'dim'),
    paint(
      [
        PACKAGE_NAME,
        'check',
        `${t.ran} of ${plural(t.selected, 'test')} run (${t.passed} passed${failed})`,
        `${t.skipped} skipped by check (PW_SEC_MAX_TESTS=${c.maxTests})`,
      ].join(' · '),
      'bold',
    ),
    '',
  ];
  const errors = c.diagnostics.filter((d) => d.level === 'error');
  const warns = c.diagnostics.filter((d) => d.level === 'warn');
  lines.push(...issueBox('error', errors, opts), ...issueBox('warn', warns, opts));

  // Scope (item 3).
  const scopeRows: TableRow[] = c.origins.map((o) => ({
    cells: [
      o.responses > 0 ? m.ok : m.warn,
      o.origin,
      o.source,
      String(o.responses),
      String(o.documents),
    ],
    ...(o.responses === 0 ? { style: 'yellow' as const } : {}),
  }));
  if (scopeRows.length === 0) {
    scopeRows.push({
      cells: [m.error, '(none: set use.baseURL or scope.origins)', '', '0', '0'],
      style: 'red',
    });
  }
  lines.push(
    ...table(
      [
        { header: '' },
        { header: 'origin in scope', flex: true, minWidth: 20 },
        { header: 'from' },
        { header: 'responses', align: 'right' },
        { header: 'documents', align: 'right' },
      ],
      scopeRows,
      opts,
    ),
    '',
  );

  // Traffic outside the scope (item 4).
  const outside = Object.entries(c.outOfScope).sort(
    ([a, x], [b, y]) => y - x || (a < b ? -1 : a > b ? 1 : 0),
  );
  if (outside.length > 0) {
    const rows: TableRow[] = outside
      .slice(0, MAX_OUT_OF_SCOPE)
      .map(([origin, n]) => ({ cells: [origin, String(n)] }));
    lines.push(
      ...table(
        [
          { header: 'outside the scope (not scanned)', flex: true, minWidth: 20 },
          { header: 'responses', align: 'right' },
        ],
        rows,
        { ...opts, border: 'dim' },
      ),
    );
    if (outside.length > MAX_OUT_OF_SCOPE) {
      lines.push(
        paint(`  … and ${plural(outside.length - MAX_OUT_OF_SCOPE, 'more origin')}`, 'dim'),
      );
    }
    lines.push(paint('  Add an origin to scope.origins if it is your app or API.', 'dim'), '');
  }

  // Facts (item 5).
  const facts: [string, string][] = [
    ['Projects', c.projects.map((p) => (p === '' ? '(default)' : p)).join(', ') || '(none)'],
    [
      'Responses',
      `${c.responses} in scope (${c.apiResponses} API, from ${plural(c.testsWithApi, 'test')})`,
    ],
    [
      'Rules',
      `${c.enabledRules} enabled (preset ${c.preset}${(c.customRules ?? 0) > 0 ? `, ${c.customRules} custom` : ''})`,
    ],
    ['Baseline', c.baseline],
    [
      'Findings',
      `${c.findings} in this check; ${c.newAboveGate} new ≥ ${c.minSeverity} against the baseline`,
    ],
  ];
  lines.push(
    ...table(
      [
        { header: '', style: 'bold' },
        { header: '', flex: true, minWidth: 10 },
      ],
      facts.map((cells) => ({ cells })),
      { ...opts, header: false },
    ),
    '',
  );

  // Verdict (item 6).
  const nothing = 'check: nothing was written';
  let verdict: [string, string, ColorStyle, ColorStyle, string];
  if (errors.length > 0 || c.responses === 0) {
    const reason =
      c.responses === 0
        ? 'NO_TRAFFIC: no response was in scope; set use.baseURL or scope.origins, and use the fixtures of withSecurityFixtures()'
        : `${[...new Set(errors.map((e) => e.code))].join(', ')}`;
    verdict = [m.error, 'NOT READY', 'red', 'badge-red', `${reason}; ${nothing}`];
  } else if (warns.length > 0 || c.origins.some((o) => o.responses === 0)) {
    verdict = [
      m.warn,
      'READY WITH WARNINGS',
      'yellow',
      'badge-yellow',
      `the scan sees ${plural(c.responses, 'response')} in scope; ${nothing}`,
    ];
  } else {
    verdict = [
      m.ok,
      'READY',
      'green',
      'badge-green',
      `the scan sees ${plural(c.responses, 'response')} in scope; ${nothing}`,
    ];
  }
  const [mark, word, color, badge, reason] = verdict;
  lines.push(
    ...boxLines(
      [
        {
          spans: [
            { text: `${mark} ` },
            { text: ` ${word} `, style: badge },
            { text: ` ${reason}` },
          ],
          indent: textWidth(mark) + word.length + 4,
        },
      ],
      { ...opts, border: color, wrap: true },
    ),
  );
  // Next (item 7).
  lines.push(
    `${paint('Next:', 'bold')} ${paint('PW_SEC_MODE=baseline npx playwright test', 'cyan')}   ${paint('(the first baseline; review it before commit)', 'dim')}`,
  );
  return lines;
}
