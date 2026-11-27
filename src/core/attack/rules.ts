// The zap.* rules of an attack run as catalog entries for the reports (19-REQ-10, 19 chapter 11a):
// built from AttackSummary.rules, the descriptions ZAP gave with its alerts. They never run.
import type { BuiltInRule } from '../rules/types.ts';
import type { AttackSummary } from '../types/index.ts';

const NEVER = (): never[] => [];

/** Catalog entries of the zap.* rules of a report; empty outside an attack run. */
export function zapRulesOf(summary: AttackSummary | null | undefined): BuiltInRule[] {
  return (summary?.rules ?? []).map((r) => ({
    id: r.id,
    appliesTo: {},
    check: NEVER,
    docs: {
      title: r.name,
      why: r.description === '' ? `${r.name} (an alert of the ZAP active scan).` : r.description,
      fix: r.solution === '' ? `See ${r.helpUri}` : r.solution,
      falsePositives:
        'An alert of the ZAP active scan: confirm it by hand (the attack and evidence are in the finding), then mark a false positive in the baseline or switch the rule off with rules["' +
        r.id +
        '"]: "off".',
      url: r.helpUri,
    },
    manifest: {
      id: r.id,
      group: 'zap',
      title: r.name,
      defaultSeverity: 'medium',
      defaultConfidence: 'medium',
      scope: 'endpoint',
      cwe: [...r.cwe],
      ...(r.owasp === null ? {} : { owasp: r.owasp }),
      sources: ['browser', 'api'],
      options: {},
    },
  }));
}
