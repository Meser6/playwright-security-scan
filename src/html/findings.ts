// The Findings tab (09, chapters 3.2, 3.3 and 3.6): the table of findings with filters, sorting
// and search, and the details block of each finding (09-REQ-20). Without the script the details
// are a <details> row under the finding (09-REQ-18). Table markup follows the key table of
// playwright-performance-regression (src/html/keys.ts, MIT, D-08).
import { ruleDocsUrl } from '../core/rules/types.ts';
import type { BuiltInRule } from '../core/rules/types.ts';
import type { ClassifiedFinding, TestContextRef } from '../core/types/index.ts';
import { CONFIDENCES, SEVERITIES, confidenceRank, severityRank } from '../core/types/index.ts';
import type { Ctx } from './context.ts';
import { html } from './escape.ts';
import type { HtmlValue, SafeHtml } from './escape.ts';
import { plural } from './format.ts';
import { icon } from './icons.ts';
import type { IconName } from './icons.ts';
import {
  CLASS_ORDER,
  REPOSITORY_URL,
  classKey,
  classPill,
  compareText,
  confidencePill,
  docText,
  emptyState,
  facts,
  join,
  pill,
  severityPill,
  sourceToken,
  subjectView,
} from './parts.ts';

/** Tests listed in the details of a finding (09-REQ-20). */
export const MAX_TESTS = 50;

const classRank = (f: ClassifiedFinding): number => CLASS_ORDER.indexOf(classKey(f));

/**
 * Default order (09, chapter 3.2): new blocking, expired, new non-blocking, then baseline
 * entries; inside a class by severity, confidence, number of tests and fingerprint.
 */
export function defaultOrder(findings: readonly ClassifiedFinding[]): ClassifiedFinding[] {
  return [...findings].sort(
    (a, b) =>
      classRank(a) - classRank(b) ||
      severityRank(b.severity) - severityRank(a.severity) ||
      confidenceRank(b.confidence) - confidenceRank(a.confidence) ||
      b.tests.length - a.tests.length ||
      compareText(a.fingerprint, b.fingerprint),
  );
}

export function testLabel(t: TestContextRef, withStep: boolean): SafeHtml {
  return html`<code>${t.file}:${t.line}</code> › ${t.titlePath.join(' › ')}${withStep && t.step !== undefined ? html` › <span class="step">${t.step}</span>` : null}`;
}

function project(t: TestContextRef): string {
  return t.project === '' ? 'default project' : t.project;
}

function part(title: string, note: HtmlValue, ...content: HtmlValue[]): SafeHtml {
  return html`<div class="ds"><h4>${title}${note === null ? null : html` <span class="sub">${note}</span>`}</h4>${content}</div>`;
}

/** A tone box: tone class of the verdict card, icon and content. */
function toneBox(tone: string, name: IconName, ...content: HtmlValue[]): SafeHtml {
  return html`<div class="bs ${tone}"><span class="bi">${icon(name)}</span><div>${content}</div></div>`;
}

/** The state of a finding against the baseline (09-REQ-20, item 3). */
function baselineState(ctx: Ctx, f: ClassifiedFinding): SafeHtml {
  const gate = ctx.report.gate;
  const gateText = `severity ≥ ${gate.minSeverity} and confidence ≥ ${gate.minConfidence}`;
  const b = f.baseline;
  if (f.classification === 'new') {
    if (f.blocking) {
      return toneBox(
        't-bad',
        'bad',
        html`<p><b>New, blocking</b>: not in the baseline, and new findings with ${gateText} fail the run.</p>`,
      );
    }
    return toneBox(
      't-warn',
      'warn',
      html`<p><b>New, not blocking</b>: not in the baseline; ${ctx.report.mode === 'baseline' ? 'this baseline run wrote it to the baseline (the gate is off).' : `below the gate (${gateText}).`}</p>`,
    );
  }
  const entry: [string, HtmlValue][] =
    b === undefined
      ? []
      : [
          [
            'Note',
            b.note === undefined || b.note === '' ? html`<span class="sub">none</span>` : b.note,
          ],
          ['Added', b.addedAt],
          ['Until', b.until ?? html`<span class="sub">no end date</span>`],
        ];
  const requireNote = ctx.config?.baseline.requireNote === true;
  const noNote =
    requireNote && b !== undefined && (b.note === undefined || b.note.trim() === '')
      ? html`<p class="warnline">${icon('warn')}<span>No note: <code>baseline.requireNote</code> expects a reason for every entry.</span></p>`
      : null;
  if (f.classification === 'expired') {
    return toneBox(
      't-bad',
      'clock',
      html`<p><b>Expired</b>: the baseline entry ended on ${b?.until ?? 'its until date'}; fix the finding, or review it and move <code>until</code>.</p>`,
      facts(entry),
      noNote,
    );
  }
  const days = b?.expiresInDays;
  return toneBox(
    't-ok',
    'ok',
    html`<p><b>In the baseline</b> as <b>${b?.status ?? f.classification}</b>: known and not blocking.</p>`,
    facts(entry),
    days === undefined
      ? null
      : html`<p class="warnline">${icon('warn')}<span>Expires in ${plural(days, 'day')} (until ${b?.until ?? ''}).</span></p>`,
    noNote,
  );
}

/** Where the finding is (09-REQ-20, item 5). */
function placeFacts(f: ClassifiedFinding): SafeHtml {
  const loc = f.location;
  const items: [string, HtmlValue][] = [['Origin', html`<code>${loc.origin}</code>`]];
  if (loc.endpointKey !== undefined) items.push(['Endpoint', subjectView(loc.endpointKey)]);
  if (loc.header !== undefined) items.push(['Header', html`<code>${loc.header}</code>`]);
  if (loc.param !== undefined) items.push(['Parameter', html`<code>${loc.param}</code>`]);
  if (f.scope === 'cookie') items.push(['Cookie', html`<code>${f.subject}</code>`]);
  if (f.scope === 'storage-key') items.push(['Storage key', html`<code>${f.subject}</code>`]);
  if (f.scope === 'asset') items.push(['Asset', html`<code>${f.subject}</code>`]);
  if (f.discriminator !== undefined) items.push(['Detail', html`<code>${f.discriminator}</code>`]);
  return facts(items);
}

function evidencePart(f: ClassifiedFinding): SafeHtml {
  if (f.evidence.length === 0) return part('Evidence', null, html`<p class="sub">none</p>`);
  return part(
    'Evidence',
    'redacted',
    html`<ul class="evl">${f.evidence.map(
      (e) =>
        html`<li><span class="src">${e.kind}</span>${e.name === undefined ? null : html`<b>${e.name}</b>`}<code class="snip">${e.snippet}</code></li>`,
    )}</ul>`,
  );
}

function testsPart(ctx: Ctx, f: ClassifiedFinding): SafeHtml {
  const first = f.firstSeen;
  const others: TestContextRef[] = [];
  let unknown = 0;
  for (const id of f.tests) {
    if (id === first.testId) continue;
    const ref = ctx.tests.get(id);
    if (ref === undefined) unknown++;
    else others.push(ref);
  }
  const shown = others.slice(0, MAX_TESTS - 1);
  const more = others.length - shown.length + unknown;
  return part(
    'Tests',
    `${plural(f.occurrences, 'occurrence')} in ${plural(f.tests.length, 'test')}`,
    html`<ul class="tl two">`,
    html`<li class="first"><span class="tt"><span>${testLabel(first, true)}</span><span class="sub">${project(first)}</span></span><span class="num">${pill('p', 'first seen')}</span></li>`,
    shown.map(
      (t) =>
        html`<li><span class="tt"><span>${testLabel(t, false)}</span><span class="sub">${project(t)}</span></span></li>`,
    ),
    more > 0 ? html`<li class="sub">and ${plural(more, 'more test')}</li>` : null,
    html`</ul>`,
  );
}

/** The "custom" badge of a custom rule (16-REQ-12). */
function customBadge(rule: BuiltInRule | undefined): SafeHtml | null {
  return rule?.manifest.group === 'custom' ? html` <span class="src">custom</span>` : null;
}

function referencesPart(ctx: Ctx, ruleId: string): SafeHtml {
  const m = ctx.rules.get(ruleId)?.manifest;
  const items: [string, HtmlValue][] = [];
  for (const cwe of m?.cwe ?? []) {
    items.push([
      `CWE-${String(cwe)}`,
      html`<code>https://cwe.mitre.org/data/definitions/${cwe}.html</code>`,
    ]);
  }
  if (m?.owasp !== undefined) items.push(['OWASP', m.owasp]);
  const rule = ctx.rules.get(ruleId);
  const docsUrl =
    rule === undefined
      ? `${REPOSITORY_URL}/blob/main/docs/rules/${ruleId}.md`
      : ruleDocsUrl(rule, REPOSITORY_URL);
  if (docsUrl !== undefined) items.push(['Rule docs', html`<code>${docsUrl}</code>`]);
  return part('References', 'addresses as text', facts(items));
}

/**
 * Why, Fix, False positives and references of one rule (09-REQ-20, items 8 and 9), rendered once
 * per rule: the details of a finding point to it, and the script copies it into the details when
 * they open (09, chapter 3.7). Keeps 1000 findings under 5 MB (09-AC-02).
 */
function ruleDoc(ctx: Ctx, ruleId: string): SafeHtml {
  const rule = ctx.rules.get(ruleId);
  const docs = rule?.docs;
  return join(
    html`<section class="rdoc" id="rule-${ruleId}" data-rule="${ruleId}"><h4 class="rt">${docs?.title ?? ruleId} <code class="rid">${ruleId}</code>${customBadge(rule)}</h4>`,
    docs === undefined
      ? null
      : [
          part('Why', null, html`<div class="doc">${docText(docs.why)}</div>`),
          part('Fix', null, html`<div class="doc">${docText(docs.fix)}</div>`),
          docs.falsePositives === ''
            ? null
            : part(
                'False positives',
                null,
                html`<div class="doc">${docText(docs.falsePositives)}</div>`,
              ),
        ],
    referencesPart(ctx, ruleId),
    html`</section>`,
  );
}

/** The rule reference under the findings table: one block per rule with findings. */
function ruleReference(ctx: Ctx, findings: readonly ClassifiedFinding[]): SafeHtml {
  const ids = [...new Set(findings.map((f) => f.ruleId))].sort(compareText);
  return html`<details class="card cfg rref-all" id="rule-docs"><summary>Rule reference: why it matters, how to fix it, false positives (${plural(ids.length, 'rule')})</summary><div class="rdocs">${ids.map((id) => ruleDoc(ctx, id))}</div></details>`;
}

function copyButton(label: string): SafeHtml {
  return html`<button type="button" class="btn sm js-only" data-copy-prev aria-label="${label}" hidden>${icon('copy')}Copy</button>`;
}

/** A ready baseline entry for findings that are not in the baseline (09-REQ-20, item 10). */
function acceptPart(ctx: Ctx, f: ClassifiedFinding): SafeHtml | null {
  if (f.classification !== 'new' && f.classification !== 'expired') return null;
  const entry = {
    [f.fingerprint]: {
      ruleId: f.ruleId,
      subject: f.subject,
      severity: f.severity,
      status: 'accepted',
      note: '',
      until: '',
      addedAt: ctx.today,
    },
  };
  return part(
    'Accept',
    'add to security-baseline.json, fill in "note" (and "until" or remove it), commit after review',
    html`<div class="cp"><pre class="code">${JSON.stringify(entry, null, 2)}</pre>${copyButton('Copy the baseline entry')}</div>`,
  );
}

/** Header of the details block: rule title, id, pills and counts (09-REQ-20, item 1). */
function findingHeader(ctx: Ctx, f: ClassifiedFinding): SafeHtml {
  const rule = ctx.rules.get(f.ruleId);
  const title = rule?.docs.title ?? f.ruleId;
  return html`<div class="kh"><p class="fkl"><span class="ft">${title}</span> <code class="rid">${f.ruleId}</code>${customBadge(rule)}</p><p class="pills">${[
    severityPill(f.severity),
    confidencePill(f.confidence),
    classPill(f),
    f.sources.map(sourceToken),
  ]}<span class="sub">${plural(f.occurrences, 'occurrence')} · ${plural(f.tests.length, 'test')}</span></p></div>`;
}

/** Content of the details block of a finding, in the order of 09-REQ-20. */
export function findingDetails(ctx: Ctx, f: ClassifiedFinding): SafeHtml {
  return join(
    html`<div class="kd">`,
    findingHeader(ctx, f),
    html`<p class="msg">${f.message}</p>`,
    baselineState(ctx, f),
    part(
      'Fingerprint',
      null,
      html`<div class="cp"><code class="fp">${f.fingerprint}</code>${copyButton('Copy the fingerprint')}</div>`,
    ),
    part('Location', null, placeFacts(f)),
    evidencePart(f),
    testsPart(ctx, f),
    html`<div class="ds rref" data-rule="${f.ruleId}"><h4>Why, fix and false positives</h4><p><a href="#rule-${f.ruleId}">Rule reference of <code>${f.ruleId}</code></a></p></div>`,
    acceptPart(ctx, f),
    html`</div>`,
  );
}

const ROW_CLASS: Record<string, string> = {
  blocking: 'blocking',
  expired: 'expired',
  new: 'new',
};

function findingRow(ctx: Ctx, f: ClassifiedFinding, index: number): SafeHtml {
  const rule = ctx.rules.get(f.ruleId);
  const title = rule?.docs.title ?? f.ruleId;
  const key = classKey(f);
  return join(
    html`<tbody data-c="${key}" data-sev="${f.severity}" data-conf="${f.confidence}" data-grp="${rule?.manifest.group ?? ''}" data-org="${f.location.origin}" data-fp="${f.fingerprint}" data-o="${index}" data-sv="${severityRank(f.severity)}" data-cv="${confidenceRank(f.confidence)}" data-occ="${f.occurrences}" data-tn="${f.tests.length}" data-cr="${CLASS_ORDER.indexOf(key)}">`,
    html`<tr class="${ROW_CLASS[key] ?? 'base'}">`,
    html`<td>${severityPill(f.severity)}</td><td class="cf">${f.confidence}</td>`,
    html`<th scope="row" class="rk"><a class="kl" href="#f-${index}"><span class="key">${f.ruleId}</span></a>${customBadge(rule)}<small class="why">${title}</small></th>`,
    html`<td class="subj"><span class="sv">${subjectView(f.subject)}</span>${f.discriminator === undefined ? null : html`<small class="why">${f.discriminator}</small>`}</td>`,
    html`<td class="num">${f.occurrences}</td><td class="num">${f.tests.length}</td><td>${classPill(f)}</td></tr>`,
    html`<tr class="drow"><td colspan="7"><details id="f-${index}"${key === 'blocking' || key === 'expired' ? html` data-v=""` : null}><summary>Details</summary>`,
    findingDetails(ctx, f),
    html`</details></td></tr></tbody>`,
  );
}

function chip(group: string, value: string, label: HtmlValue): SafeHtml {
  return html`<button type="button" class="flt" aria-pressed="false" data-f="${group}" data-v="${value}">${label}</button>`;
}

function select(name: string, label: string, values: readonly string[]): SafeHtml | null {
  if (values.length < 2) return null;
  return html`<label class="fsel"><span>${label}</span><select data-sel="${name}"><option value="">all</option>${values.map((v) => html`<option value="${v}">${v}</option>`)}</select></label>`;
}

function toolbar(findings: readonly ClassifiedFinding[], ctx: Ctx): SafeHtml {
  const groups = [
    ...new Set(findings.map((f) => ctx.rules.get(f.ruleId)?.manifest.group ?? '')),
  ].sort(compareText);
  const origins = [...new Set(findings.map((f) => f.location.origin))].sort(compareText);
  return join(
    html`<div class="toolbar js-only" hidden>`,
    html`<label class="search">${icon('search')}<input type="search" aria-label="Search findings" placeholder="Filter by rule, subject or test…" autocomplete="off"></label>`,
    html`<div class="fg" role="group" aria-label="Classification"><span aria-hidden="true">Classification</span>${[
      chip('c', 'blocking', 'new · blocking'),
      chip('c', 'new', 'new'),
      chip('c', 'expired', 'expired'),
      chip('c', 'accepted', 'accepted'),
      chip('c', 'wontfix', 'wontfix'),
      chip('c', 'false-positive', 'false positive'),
    ]}</div>`,
    html`<div class="fg" role="group" aria-label="Severity"><span aria-hidden="true">Severity</span>${[...SEVERITIES].reverse().map((s) => chip('sev', s, s))}</div>`,
    html`<div class="fg" role="group" aria-label="Confidence"><span aria-hidden="true">Confidence</span>${[...CONFIDENCES].reverse().map((c) => chip('conf', c, c))}</div>`,
    select('grp', 'Rule group', groups),
    select('org', 'Origin', origins),
    html`<button type="button" class="btn sm" data-reset>Reset</button>`,
    html`<span class="count" role="status" data-count>showing ${findings.length} of ${findings.length}</span></div>`,
  );
}

const COLUMNS: [column: string, label: string, numeric: boolean][] = [
  ['sev', 'Severity', false],
  ['conf', 'Confidence', false],
  ['rule', 'Rule', false],
  ['subject', 'Subject', false],
  ['occ', 'Occurrences', true],
  ['tests', 'Tests', true],
  ['cls', 'Classification', false],
];

/** Content of the Findings tab (09, chapter 3.2). */
export function findingsTab(ctx: Ctx): SafeHtml {
  const findings = defaultOrder(ctx.report.findings);
  if (findings.length === 0) {
    return emptyState(
      'No findings',
      ctx.report.coverage.responses === 0
        ? 'No response was in scope, so the rules had nothing to check; see Coverage.'
        : 'The rules found nothing in the traffic in scope.',
    );
  }
  return join(
    html`<div class="card" data-for="table-findings">`,
    toolbar(findings, ctx),
    html`<div class="scroll" tabindex="0" role="region" aria-label="Findings table"><table class="keys findings" id="table-findings">`,
    html`<caption>Findings: ${plural(findings.length, 'finding')}, new blocking first</caption>`,
    html`<thead><tr>${COLUMNS.map(
      ([column, label, numeric]) =>
        html`<th scope="col" data-sort="${column}"${numeric ? html` class="num"` : null}><button type="button">${label}</button></th>`,
    )}</tr></thead>`,
    findings.map((f, i) => findingRow(ctx, f, i)),
    html`</table></div>`,
    html`<div class="empty sm" data-none hidden>${icon('search')}<p>No findings match the filters</p><button type="button" class="btn sm" data-reset>Reset</button></div>`,
    html`<p class="tfoot">Severity and confidence after the config · evidence is redacted · a finding is one fingerprint, seen in one or more tests</p></div>`,
    ruleReference(ctx, findings),
  );
}
