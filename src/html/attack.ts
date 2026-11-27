// The Attack tab (19-REQ-10): ZAP version, role, duration, requests, alerts and the budget of the
// active scan. The zap.* findings are in the Findings tab with the ZAP badge.
import type { Ctx } from './context.ts';
import { html } from './escape.ts';
import type { SafeHtml } from './escape.ts';
import { plural } from './format.ts';
import { emptySmall, facts, join, section } from './parts.ts';

/** Content of the Attack tab (19-REQ-10). */
export function attackTab(ctx: Ctx): SafeHtml {
  const a = ctx.report.attack;
  if (a == null) return emptySmall('No attack in this run');
  const zapFindings = ctx.report.findings.filter((f) => f.ruleId.startsWith('zap.')).length;
  const mutating = a.methods.filter((m) => ['POST', 'PUT', 'PATCH', 'DELETE'].includes(m));
  return join(
    section(
      'attack-summary',
      'ZAP active scan',
      null,
      html`<div class="card">${facts([
        [
          'ZAP',
          `${a.zapVersion ?? 'unknown version'} (${a.zap === 'docker' ? 'container of this run' : 'attack.zapUrl'})`,
        ],
        ['Origins', a.origins.join(', ')],
        ['Role', a.role],
        [
          'Methods',
          `${a.methods.join(', ')}${mutating.length > 0 ? ' · methods that change data are attacked' : ''}`,
        ],
        ['Duration', `${String(a.durationSeconds)} s`],
        [
          'Requests',
          `${plural(a.requests, 'request')} (${String(a.templates.sent)} requests of the tests given to ZAP${a.templates.failed > 0 ? `, ${String(a.templates.failed)} failed` : ''})`,
        ],
        [
          'Alerts',
          `${String(a.alerts.mapped)} mapped to ${plural(zapFindings, 'finding')} · ${String(a.alerts.falsePositive)} false positive · ${String(a.alerts.passive)} passive (not read) · ${String(a.alerts.off)} switched off`,
        ],
        [
          'Budget',
          `${String(a.budget.maxDurationMinutes)} min, ${String(a.budget.maxRequests)} requests, ${String(a.budget.maxRps)} rps${a.budgetExceeded ? ' · used up, the scan was stopped' : ''}`,
        ],
        [
          'Result',
          a.completed
            ? 'completed within the budget'
            : 'not completed: zap.* baseline entries of this run stay not covered',
        ],
      ])}</div>`,
    ),
  );
}
