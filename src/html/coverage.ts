// The Coverage tab (09-REQ-04, 09-REQ-05) and the Run & config tab (09-REQ-17, item 4), as cards
// like the Run & config tab of playwright-performance-regression (src/html/run.ts, MIT, D-08).
import type { Diagnostic, EntryRef } from '../core/types/index.ts';
import type { Ctx } from './context.ts';
import { html } from './escape.ts';
import type { HtmlValue, SafeHtml } from './escape.ts';
import { testLabel } from './findings.ts';
import { formatDate, formatRunDuration, plural } from './format.ts';
import { icon } from './icons.ts';
import {
  DASH,
  REPOSITORY_URL,
  compareText,
  emptySmall,
  facts,
  join,
  section,
  subjectView,
} from './parts.ts';

/** The fixed box of what a passive scan does not see (09-REQ-05). */
function notCoveredBox(authz: boolean): SafeHtml {
  const what = authz
    ? 'It looks at the traffic of your tests; its only own requests are the authorization tests: GET/HEAD replays only. It does not send attacks (no injection tests), does not see'
    : 'It is passive: it only looks at the traffic of your tests. It does not send attacks (no injection or authorization tests), does not see';
  return html`<div class="note warnbox">${icon('info')}<span><b>What this scan does not cover.</b> ${what} endpoints your tests never call, WebSockets or Server-Sent Events, and does not judge business logic. It does not replace a penetration test. Active checks are planned: <code>${REPOSITORY_URL}#what-it-does-not-do</code>.</span></div>`;
}

function countList(counts: Record<string, number>): string {
  const keys = Object.keys(counts).sort(compareText);
  return keys.length === 0 ? 'none' : keys.map((k) => `${k} ${String(counts[k])}`).join(', ');
}

function entryList(
  id: string,
  title: string,
  entries: readonly EntryRef[],
  note: string,
): SafeHtml {
  return section(
    id,
    title,
    entries.length,
    html`<div class="card">${
      entries.length === 0
        ? emptySmall('none')
        : html`<ul class="tl two">${entries.map(
            (e) =>
              html`<li><span class="tt"><span><code>${e.ruleId}</code> · ${e.subject}</span><span class="sub">${e.fingerprint}</span></span></li>`,
          )}</ul><p class="tfoot">${note}</p>`
    }</div>`,
  );
}

/** Content of the Coverage tab (09-REQ-04, 09-REQ-05). */
export function coverageTab(ctx: Ctx): SafeHtml {
  const r = ctx.report;
  const c = r.coverage;
  const origins = Object.keys(c.origins).sort(compareText);
  const endpoints = Object.keys(c.endpoints).sort(compareText);
  const outOfScope = c.outOfScopeOrigins ?? {};
  const enabled =
    ctx.config === null
      ? []
      : Object.keys(ctx.config.rules).filter((id) => ctx.config?.rules[id]?.enabled === true);
  const noInput = enabled.filter((id) => (c.rulesRun[id] ?? 0) === 0).sort(compareText);
  return join(
    notCoveredBox(r.authz != null),
    section(
      'cov-traffic',
      'Traffic',
      null,
      html`<div class="card">${facts([
        [
          'In scope',
          `${plural(c.responses, 'response')} (${String(c.apiResponses)} from API tests)`,
        ],
        [
          'Out of scope',
          `${plural(c.outOfScope, 'response')}${Object.keys(outOfScope).length === 0 ? '' : `: ${countList(outOfScope)}`}`,
        ],
        ['Documents', String(c.documents)],
        ['Bodies analysed', String(c.bodiesAnalyzed)],
        ['Bodies skipped', countList(c.bodiesSkipped)],
        ['Assets', String(c.assets.length)],
        ['Storage origins', c.storageOrigins.length === 0 ? 'none' : c.storageOrigins.join(', ')],
      ])}</div>`,
    ),
    section(
      'cov-origins',
      'Origins',
      origins.length,
      html`<div class="card">${
        origins.length === 0
          ? emptySmall('No response in scope')
          : html`<div class="scroll" tabindex="0" role="region" aria-label="Origins table"><table><thead><tr><th scope="col">Origin</th><th scope="col" class="num">Responses</th><th scope="col" class="num">Documents</th></tr></thead><tbody>${origins.map(
              (o) =>
                html`<tr><th scope="row"><code>${o}</code></th><td class="num">${c.origins[o]?.responses ?? 0}</td><td class="num">${c.origins[o]?.documents ?? 0}</td></tr>`,
            )}</tbody></table></div>`
      }</div>`,
    ),
    section(
      'cov-endpoints',
      'Endpoints',
      endpoints.length,
      endpoints.length === 0
        ? html`<div class="card">${emptySmall('No endpoint in scope')}</div>`
        : html`<details class="card cfg"><summary>${plural(endpoints.length, 'endpoint')} with the number of responses</summary><div class="scroll" tabindex="0" role="region" aria-label="Endpoints table"><table><thead><tr><th scope="col">Endpoint</th><th scope="col" class="num">Responses</th></tr></thead><tbody>${endpoints.map(
            (e) =>
              html`<tr><th scope="row" class="ep">${subjectView(e)}</th><td class="num">${c.endpoints[e] ?? 0}</td></tr>`,
          )}</tbody></table></div></details>`,
    ),
    section(
      'cov-no-traffic',
      'Tests without traffic in scope',
      r.testsWithoutTraffic.length,
      html`<div class="card">${
        r.testsWithoutTraffic.length === 0
          ? emptySmall('none')
          : html`<ul class="tl two">${r.testsWithoutTraffic.map(
              (t) =>
                html`<li><span class="tt"><span>${testLabel(t, false)}</span><span class="sub">${t.project === '' ? 'default project' : t.project}</span></span></li>`,
            )}</ul><p class="tfoot">A browser context created by hand and not passed to security.track() is not scanned.</p>`
      }</div>`,
    ),
    section(
      'cov-no-input',
      'Rules that had nothing to check',
      noInput.length,
      html`<div class="card">${
        noInput.length === 0
          ? emptySmall('Every enabled rule had input')
          : html`<p class="card-p cl">${noInput.map((id) => html`<code>${id}</code> `)}</p><p class="tfoot">Enabled rules without any input in this run, e.g. cookie rules when no cookie was set.</p>`
      }</div>`,
    ),
    entryList(
      'cov-resolved',
      'Resolved baseline entries',
      r.resolved,
      'Not seen in this run: run PW_SEC_MODE=baseline to remove them.',
    ),
    entryList(
      'cov-not-covered',
      'Baseline entries not covered by this run',
      r.notCovered,
      'The run did not check these entries (rule off or no traffic to their origin), so they are kept.',
    ),
  );
}

const LEVEL_ORDER: Record<Diagnostic['level'], number> = { error: 0, warn: 1, info: 2 };

function diagnosticCard(d: Diagnostic): SafeHtml {
  const tone = d.level === 'error' ? ' err' : d.level === 'info' ? ' inf' : '';
  return html`<article class="card wn${tone}"><span class="wi">${icon(d.level === 'error' ? 'bad' : d.level === 'warn' ? 'warn' : 'info')}</span><code>${d.code}</code><span class="n ${d.level === 'error' ? 'bad' : d.level === 'warn' ? 'warn' : ''}">${d.level}</span><p>${d.message}</p></article>`;
}

/** Content of the Run & config tab (09-REQ-17, item 4). */
export function runTab(ctx: Ctx): SafeHtml {
  const r = ctx.report;
  const cfg = ctx.config;
  const diagnostics = [...r.diagnostics].sort(
    (a, b) => LEVEL_ORDER[a.level] - LEVEL_ORDER[b.level] || compareText(a.code, b.code),
  );
  const enabled =
    cfg === null
      ? []
      : Object.keys(cfg.rules)
          .filter((id) => cfg.rules[id]?.enabled === true)
          .sort(compareText);
  const run: [string, HtmlValue][] = [
    [
      'Mode',
      `${r.mode} · ${r.attack == null ? 'passive only' : 'passive + ZAP active scan'}${r.authz == null ? '' : ' + authorization tests'}`,
    ],
    ['Run ID', r.runId === '' ? DASH : html`<code>${r.runId}</code>`],
    ['Started', formatDate(r.startedAt)],
    ['Finished', formatDate(r.finishedAt)],
    ['Duration', formatRunDuration(r.startedAt, r.finishedAt)],
    ['Package', `playwright-security-scan ${r.pkgVersion}`],
    ['Playwright', r.playwrightVersion === '' ? DASH : r.playwrightVersion],
    [
      'Scope',
      r.scope.origins.length === 0
        ? 'none'
        : html`${r.scope.origins.map((o) => html`<code>${o}</code> `)}`,
    ],
    [
      'Gate',
      `new findings with severity ≥ ${r.gate.minSeverity} and confidence ≥ ${r.gate.minConfidence}`,
    ],
  ];
  if (r.shards != null) {
    const shards = r.shards;
    run.push([
      'Shards',
      html`merged from ${shards.list.map((s) => `${String(s.index)}/${String(shards.total)}`).join(', ')}${shards.missing.length > 0 ? html` · <b>missing ${shards.missing.map((n) => `${String(n)}/${String(shards.total)}`).join(', ')}</b>` : null}`,
    ]);
  }
  if (cfg !== null) {
    run.push(
      [
        'Baseline',
        html`<code>${cfg.baseline.path}</code>${cfg.baseline.requireNote ? ' · note required' : null}`,
      ],
      ['Expired entries', cfg.gate.failOnExpired ? 'fail the run' : 'warn only'],
      ['No traffic', cfg.gate.failOnNoTraffic ? 'fails the run' : 'warns only'],
    );
  }
  return join(
    section('run-h', 'Run', null, html`<div class="card">${facts(run)}</div>`),
    cfg === null
      ? null
      : section(
          'rules-h',
          'Rules',
          enabled.length,
          html`<details class="card cfg"><summary>${plural(enabled.length, 'rule')} enabled · preset ${cfg.preset}</summary><div class="scroll" tabindex="0" role="region" aria-label="Rules table"><table><thead><tr><th scope="col">Rule</th><th scope="col">Severity</th><th scope="col">Confidence</th><th scope="col" class="num">Evaluations</th></tr></thead><tbody>${enabled.map(
            (id) =>
              html`<tr><th scope="row"><code>${id}</code></th><td>${cfg.rules[id]?.severity ?? DASH}</td><td>${cfg.rules[id]?.confidence ?? DASH}</td><td class="num">${r.coverage.rulesRun[id] ?? 0}</td></tr>`,
          )}</tbody></table></div></details>`,
        ),
    cfg === null
      ? null
      : section(
          'config-h',
          'Configuration',
          null,
          html`<details class="card cfg"><summary>Resolved configuration (defaults applied)</summary><pre>${JSON.stringify({ ...cfg, customRules: cfg.customRules.map((r) => r.id) }, null, 2)}</pre></details>`,
        ),
    section(
      'diag-h',
      'Diagnostics',
      diagnostics.length,
      diagnostics.length === 0
        ? html`<div class="card">${emptySmall('No errors, warnings or notes.')}</div>`
        : html`<div class="wl">${diagnostics.map(diagnosticCard)}</div>`,
    ),
  );
}
