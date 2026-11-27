// The Authorization tab (18-REQ-21): roles, replays, budget and the matrix of endpoint keys by
// role pair. A bypassed cell links to the finding dialog (09-REQ-19).
import type { AuthzSummary } from '../core/types/index.ts';
import type { Ctx } from './context.ts';
import { html } from './escape.ts';
import type { SafeHtml } from './escape.ts';
import { plural } from './format.ts';
import { compareText, emptySmall, facts, join, section, subjectView } from './parts.ts';

type Row = AuthzSummary['matrix'][number];

const LABEL: Record<Row['result'], string> = {
  enforced: 'enforced',
  bypassed: 'bypassed',
  different: 'different',
  public: 'public',
  skipped: 'skipped',
};

const TONE: Record<Row['result'], string> = {
  enforced: 'ok',
  bypassed: 'bad',
  different: '',
  public: '',
  skipped: 'warn',
};

function cell(row: Row | undefined): SafeHtml {
  if (row === undefined) return html`<td class="dim">—</td>`;
  const text = `${LABEL[row.result]}${row.result === 'skipped' && row.reason !== undefined ? ` (${row.reason})` : ''}${row.similarity === undefined || row.result === 'enforced' ? '' : ` · ${row.similarity.toFixed(2)}`}`;
  const tone = TONE[row.result];
  if (row.fingerprint !== undefined) {
    return html`<td><a class="n ${tone}" href="#finding=${encodeURIComponent(row.fingerprint)}">${text}</a></td>`;
  }
  return html`<td><span class="n ${tone}">${text}</span></td>`;
}

/** Content of the Authorization tab (18-REQ-21). */
export function authzTab(ctx: Ctx): SafeHtml {
  const a = ctx.report.authz;
  if (a == null) return emptySmall('The authorization tests are off');
  const pairs = [...new Set(a.matrix.map((m) => `${m.from} → ${m.as}`))].sort(compareText);
  const keys = [...new Set(a.matrix.map((m) => m.endpointKey))].sort(compareText);
  const byCell = new Map(a.matrix.map((m) => [`${m.endpointKey}\u0000${m.from} → ${m.as}`, m]));
  const skipped = Object.entries(a.skipped);
  return join(
    section(
      'authz-summary',
      'Replays',
      null,
      html`<div class="card">${facts([
        [
          'Roles',
          a.roles.length === 0
            ? 'none (only replays without a session)'
            : a.roles
                .map(
                  (r) =>
                    `${r.name}${r.level === null ? '' : ` (level ${String(r.level)})`}${r.projects.length > 1 || r.projects[0] !== r.name ? `: ${r.projects.join(', ')}` : ''}`,
                )
                .join(' · ') + ' · anonymous',
        ],
        ['Templates', String(a.templates)],
        ['Replays', `${plural(a.replays, 'request')} sent (GET/HEAD only)`],
        [
          'Budget',
          `${String(a.budget.used)} of ${String(a.budget.maxRequests)} requests${a.budget.exceeded ? ' · used up, the rest was skipped' : ''}`,
        ],
        [
          'Skipped',
          skipped.length === 0 ? 'none' : skipped.map(([k, n]) => `${k} ${String(n)}`).join(', '),
        ],
      ])}</div>`,
    ),
    section(
      'authz-matrix',
      'Endpoints by role pair',
      keys.length,
      html`<div class="card">${
        keys.length === 0
          ? emptySmall('No request was replayed')
          : html`<div class="scroll" tabindex="0" role="region" aria-label="Authorization matrix"><table><thead><tr><th scope="col">Endpoint</th>${pairs.map(
              (p) => html`<th scope="col">${p}</th>`,
            )}</tr></thead><tbody>${keys.map(
              (k) =>
                html`<tr><th scope="row" class="ep">${subjectView(k)}</th>${pairs.map((p) =>
                  cell(byCell.get(`${k}\u0000${p}`)),
                )}</tr>`,
            )}</tbody></table></div><p class="tfoot">enforced: denied or a sign-in page · bypassed: answered like for the original user (a finding) · different: another answer · public: seen without a session in the tests, not tested.</p>`
      }</div>`,
    ),
  );
}
