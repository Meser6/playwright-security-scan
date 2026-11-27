// Verdict card and counter tiles (09-REQ-17, items 2 and 3). Markup and classes follow the
// verdict card and KPI strip of playwright-performance-regression (src/html/overview.ts, MIT,
// D-08); the sentence is the console verdict (04-REQ-08).
import { marks } from '../core/report/term/box.ts';
import { verdict } from '../core/report/console.ts';
import type { RunReport } from '../core/types/index.ts';
import type { Ctx } from './context.ts';
import { html } from './escape.ts';
import type { HtmlValue, SafeHtml } from './escape.ts';
import { plural } from './format.ts';
import { icon } from './icons.ts';
import type { IconName } from './icons.ts';
import { join } from './parts.ts';

export type VerdictWord = 'PASSED' | 'PASSED WITH WARNINGS' | 'FAILED' | 'ERROR';

const TONE: Record<string, string> = {
  ERROR: 't-err',
  FAILED: 't-bad',
  'PASSED WITH WARNINGS': 't-warn',
  PASSED: 't-ok',
};
const TONE_ICON: Record<string, IconName> = {
  ERROR: 'warn',
  FAILED: 'bad',
  'PASSED WITH WARNINGS': 'warn',
  PASSED: 'ok',
};

/** Word and sentence of the verdict, as in the console (04-REQ-08). */
export function banner(report: RunReport): { word: string; sentence: string } {
  const [, word, , , sentence] = verdict(report, marks(true));
  return { word, sentence };
}

function result(label: string, dot: string, word: string, details: HtmlValue): SafeHtml {
  return html`<div class="ss"><dt>${label}</dt><dd><span class="dot ${dot}"></span>${word}${details === null || details === '' ? null : html` <span class="sub">${details}</span>`}</dd></div>`;
}

function results(report: RunReport): SafeHtml {
  const o = report.outcome;
  const errors = report.diagnostics.filter((d) => d.level === 'error').length;
  const warnings = report.diagnostics.filter((d) => d.level === 'warn').length;
  const security =
    o.code === 0
      ? result('Security', 'd-ok', 'passed', report.mode === 'baseline' ? 'baseline run' : null)
      : o.code === 3
        ? result('Security', 'd-bad', 'error', 'not trustworthy')
        : result(
            'Security',
            'd-bad',
            'failed',
            o.code === 1
              ? `${String(o.newBlocking)} new blocking`
              : o.code === 2
                ? `${String(o.expired)} expired`
                : 'no traffic in scope',
          );
  return html`<dl class="subst">${[
    security,
    report.outcome.testsPassed
      ? result('Tests', 'd-ok', 'passed', null)
      : result('Tests', 'd-warn', 'not all passed', 'findings may be incomplete'),
    errors > 0
      ? result(
          'Tool',
          'd-bad',
          plural(errors, 'error'),
          warnings > 0 ? plural(warnings, 'warning') : null,
        )
      : warnings > 0
        ? result('Tool', 'd-warn', plural(warnings, 'warning'), null)
        : result('Tool', 'd-ok', 'no problems', null),
  ]}</dl>`;
}

/** The verdict card (09-REQ-17, item 2). */
export function verdictCard(ctx: Ctx): SafeHtml {
  const r = ctx.report;
  const { word, sentence } = banner(r);
  return join(
    html`<section class="hero ${TONE[word] ?? 't-err'}" aria-labelledby="vh"><div class="verdict"><span class="v-ic">${icon(TONE_ICON[word] ?? 'warn')}</span><div>`,
    html`<p class="eyebrow">Scan verdict</p><h1 class="status" id="vh">${word}</h1>`,
    html`<p class="summary">${sentence}<span class="sub">exit code ${String(r.outcome.code)} · passive scan</span></p>`,
    html`</div></div>`,
    results(r),
    html`</section>`,
  );
}

interface Tile {
  label: string;
  value: number;
  note: string;
  /** Tone class when the value is above 0. */
  tone: string;
  /** Target of the link: the Findings tab with a classification filter, or a Coverage list. */
  href: string;
  filter: string | null;
}

/** The counter tiles (09-REQ-17, item 3). */
export function kpis(ctx: Ctx): SafeHtml {
  const r = ctx.report;
  const count = (test: (c: string, blocking: boolean) => boolean): number =>
    r.findings.filter((f) => test(f.classification, f.blocking)).length;
  const wontfix = count((c) => c === 'wontfix');
  const falsePositive = count((c) => c === 'false-positive');
  const gate = `severity ≥ ${r.gate.minSeverity}`;
  const tiles: Tile[] = [
    {
      label: 'New, blocking',
      value: count((c, b) => c === 'new' && b),
      note: r.mode === 'baseline' ? 'gate off (baseline run)' : gate,
      tone: 'bad',
      href: '#tab-findings',
      filter: 'blocking',
    },
    {
      label: 'New, non-blocking',
      value: count((c, b) => c === 'new' && !b),
      note: 'below the gate',
      tone: 'warn',
      href: '#tab-findings',
      filter: 'new',
    },
    {
      label: 'Accepted',
      value: count((c) => c === 'accepted') + wontfix + falsePositive,
      note: `${String(wontfix)} wontfix · ${String(falsePositive)} false positive`,
      tone: 'mute',
      href: '#tab-findings',
      filter: 'accepted wontfix false-positive',
    },
    {
      label: 'Expired',
      value: count((c) => c === 'expired'),
      note: 'baseline entries past until',
      tone: 'bad',
      href: '#tab-findings',
      filter: 'expired',
    },
    {
      label: 'Resolved',
      value: r.resolved.length,
      note: 'baseline entries not seen',
      tone: 'ok',
      href: '#cov-resolved',
      filter: null,
    },
    {
      label: 'Not covered',
      value: r.notCovered.length,
      note: 'baseline entries not checked',
      tone: 'mute',
      href: '#cov-not-covered',
      filter: null,
    },
  ];
  return html`<dl class="kpis">${tiles.map(
    (t) =>
      html`<div class="kpi${t.value > 0 ? ` ${t.tone}` : ''}"><dt>${t.label}</dt><dd class="kv">${
        t.value > 0
          ? html`<a href="${t.href}"${t.filter === null ? null : html` data-filter="${t.filter}"`}>${t.value}</a>`
          : t.value
      }</dd><dd class="ks">${t.note}</dd></div>`,
  )}</dl>`;
}
