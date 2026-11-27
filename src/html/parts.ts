// Small building blocks of the HTML report (09, chapter 3.6): pills, badges, cards, fact lists,
// empty states and the view of an endpoint. Class names and markup follow the HTML report of
// playwright-performance-regression (src/html/keys.ts, overview.ts and run.ts, MIT, D-08).
import type { ClassifiedFinding, Severity } from '../core/types/index.ts';
import { html } from './escape.ts';
import type { HtmlValue, SafeHtml } from './escape.ts';
import { icon } from './icons.ts';

export const DASH = '—';

export const REPOSITORY_URL = 'https://github.com/Meser6/playwright-security-scan';
/** The guide to the reports, shown as text in the footer (09-REQ-17). */
export const REPORTS_DOCS_URL = `${REPOSITORY_URL}/blob/main/docs/reports.md`;

/** Concatenates parts of markup. */
export function join(...parts: HtmlValue[]): SafeHtml {
  return html`${parts}`;
}

/** Code unit order, never localeCompare: the page does not depend on the machine. */
export function compareText(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

export function pill(cls: string, text: HtmlValue): SafeHtml {
  return html`<span class="pill${cls === '' ? '' : ` ${cls}`}">${text}</span>`;
}

/** A count badge of a tab or heading; `tone` is '', 'bad' or 'warn'. */
export function badge(n: number, tone = ''): SafeHtml {
  return html`<span class="n${tone === '' ? '' : ` ${tone}`}">${n}</span>`;
}

/** Severity pill in the severity colors (09-REQ-16). */
export function severityPill(severity: Severity): SafeHtml {
  return pill(`sev ${severity}`, severity);
}

/** Confidence as a neutral outlined pill. */
export function confidencePill(confidence: string): SafeHtml {
  return pill('ne', html`${confidence}<span class="sr"> confidence</span>`);
}

/**
 * Filter value of the classification of a finding: `blocking` for a new blocking finding, else
 * the classification.
 */
export function classKey(f: Pick<ClassifiedFinding, 'classification' | 'blocking'>): string {
  return f.classification === 'new' && f.blocking ? 'blocking' : f.classification;
}

/** Default order of the classifications (09, chapter 3.2): what needs action first. */
export const CLASS_ORDER: readonly string[] = [
  'blocking',
  'expired',
  'new',
  'accepted',
  'wontfix',
  'false-positive',
];

const CLASS_PILL: Record<string, [cls: string, text: string]> = {
  blocking: ['fb', 'new · blocking'],
  new: ['w', 'new'],
  expired: ['f', 'expired'],
  accepted: ['', 'accepted'],
  wontfix: ['', 'wontfix'],
  'false-positive': ['', 'false positive'],
};

/** Classification pill (09-REQ-16): solid red blocking, red expired, orange new, grey accepted. */
export function classPill(f: Pick<ClassifiedFinding, 'classification' | 'blocking'>): SafeHtml {
  const [cls, text] = CLASS_PILL[classKey(f)] ?? ['', f.classification];
  return pill(cls, text);
}

/** A source token: `browser` or `api`. */
export function sourceToken(source: string): SafeHtml {
  return html`<span class="src">${source}</span>`;
}

/** Methods with their own colour; other methods get a neutral badge. */
const METHODS: ReadonlySet<string> = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']);

export function methodBadge(method: string): SafeHtml {
  return METHODS.has(method)
    ? html`<b class="m ${method}">${method}</b>`
    : html`<b class="m">${method}</b>`;
}

/** Path parameters (`:id`, …) in the accent colour. */
function pathView(path: string): SafeHtml {
  const parts = path.split(/(?<=\/)(:[A-Za-z][\w-]*)/u);
  return html`${parts.map((part, i) => (i % 2 === 1 ? html`<i>${part}</i>` : part))}`;
}

/**
 * A subject: an endpoint key `METHOD /path` as a method badge and a monospace path with path
 * parameters in the accent colour; anything else (origin, cookie, asset) as monospace text.
 */
export function subjectView(subject: string): SafeHtml {
  const match = /^([A-Z]+) (\S.*)$/u.exec(subject);
  if (match === null) return html`<span class="key">${subject}</span>`;
  const [, method = '', path = ''] = match;
  return html`${methodBadge(method)} <span class="key">${pathView(path)}</span>`;
}

/** Label and value list in two columns. */
export function facts(items: readonly [string, HtmlValue][]): SafeHtml {
  return html`<dl class="kvl">${items.map(([k, v]) => html`<dt>${k}</dt><dd>${v}</dd>`)}</dl>`;
}

/** A section of a panel: heading with an optional badge, then the content. */
export function section(
  id: string,
  title: string,
  count: number | null,
  ...content: HtmlValue[]
): SafeHtml {
  return html`<section aria-labelledby="${id}"><div class="ph"><h3 id="${id}">${title}${count === null ? null : html` ${badge(count)}`}</h3></div>${content}</section>`;
}

/** Empty state of a run or a tab. */
export function emptyState(title: string, text: HtmlValue): SafeHtml {
  return html`<div class="card empty"><span class="ei">${icon('inbox')}</span><h3>${title}</h3><p>${text}</p></div>`;
}

/** A one-line empty note inside a card. */
export function emptySmall(text: string): SafeHtml {
  return html`<div class="empty sm">${icon('ok')}<p>${text}</p></div>`;
}

/**
 * Text of the rule docs as markup: paragraphs, `- ` lists and inline `code`. Everything else is
 * escaped text.
 */
export function docText(text: string): SafeHtml {
  const inline = (line: string): SafeHtml =>
    html`${line.split(/`([^`]+)`/u).map((part, i) => (i % 2 === 1 ? html`<code>${part}</code>` : part))}`;
  const blocks: SafeHtml[] = [];
  let items: SafeHtml[] = [];
  const flush = (): void => {
    if (items.length > 0) blocks.push(html`<ul class="plain">${items}</ul>`);
    items = [];
  };
  for (const line of text.split('\n')) {
    if (line.startsWith('- ')) {
      items.push(html`<li>${inline(line.slice(2))}</li>`);
      continue;
    }
    flush();
    if (line.trim() !== '') blocks.push(html`<p>${inline(line)}</p>`);
  }
  flush();
  return join(blocks);
}
