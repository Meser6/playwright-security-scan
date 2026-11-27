// JUnit XML (09, chapter 6): one suite per rule group, one test case per finding. Pure.
import type { RuleGroup } from '../manifest/rules.ts';
import { ruleManifest } from '../manifest/rules.ts';
import type { BuiltInRule } from '../rules/index.ts';
import type { ClassifiedFinding, RunReport } from '../types/index.ts';
import { testLabel } from './console.ts';

const GROUPS: RuleGroup[] = [
  'header',
  'cookie',
  'cors',
  'transport',
  'data',
  'disclosure',
  'browser',
  'auth',
  'cache',
  'custom',
];

/** XML text: escapes markup and drops characters XML 1.0 does not allow. */
export function xml(text: string): string {
  return (
    text
      // eslint-disable-next-line no-control-regex
      .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f￾￿]/g, '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
  );
}

function body(f: ClassifiedFinding, rule: BuiltInRule | undefined): string {
  const lines = [
    f.message,
    '',
    `Subject: ${f.subject}${f.discriminator === undefined ? '' : ` (${f.discriminator})`}`,
    `Severity/confidence: ${f.severity}/${f.confidence} · occurrences: ${f.occurrences} · sources: ${f.sources.join(', ')}`,
    `First seen: ${testLabel(f.firstSeen)}`,
  ];
  if (f.evidence.length > 0) {
    lines.push('', 'Evidence:');
    for (const e of f.evidence)
      lines.push(`  ${e.kind}${e.name === undefined ? '' : ` ${e.name}`}: ${e.snippet}`);
  }
  if (rule !== undefined) lines.push('', 'Fix:', rule.docs.fix);
  lines.push(
    '',
    'Accept in security-baseline.json (review first):',
    JSON.stringify(
      {
        [f.fingerprint]: {
          ruleId: f.ruleId,
          subject: f.subject,
          severity: f.severity,
          status: 'accepted',
          note: '',
          addedAt: 'YYYY-MM-DD',
        },
      },
      null,
      2,
    ),
  );
  return lines.join('\n');
}

/** The JUnit XML text of a run (09-REQ-10 … 09-REQ-14). */
export function buildJunit(
  report: RunReport,
  rules: readonly BuiltInRule[],
  options: { includeAccepted: boolean; failOnExpired: boolean },
): string {
  const byId = new Map(rules.map((r) => [r.id, r]));
  const suites: string[] = [];
  let total = 0;
  let failures = 0;
  let errors = 0;
  let skipped = 0;

  if (report.outcome.code === 3) {
    const text = report.diagnostics
      .filter((d) => d.level === 'error')
      .map((d) => `${d.code}: ${d.message}`)
      .join('\n');
    suites.push(
      `  <testsuite name="pw-sec" tests="1" failures="0" errors="1" skipped="0" time="0">\n    <testcase classname="pw-sec" name="pw-sec" time="0">\n      <error type="TOOL_ERROR" message="${xml('the scan could not complete')}">${xml(text)}</error>\n    </testcase>\n  </testsuite>`,
    );
    total += 1;
    errors += 1;
  }

  for (const group of GROUPS) {
    const cases: string[] = [];
    let f1 = 0;
    let s1 = 0;
    for (const f of report.findings) {
      const ruleGroup = byId.get(f.ruleId)?.manifest.group ?? ruleManifest(f.ruleId)?.group;
      if ((ruleGroup ?? (f.ruleId.startsWith('custom.') ? 'custom' : 'browser')) !== group) {
        continue;
      }
      const accepted =
        f.classification === 'accepted' ||
        f.classification === 'wontfix' ||
        f.classification === 'false-positive';
      if (accepted && !options.includeAccepted) continue;
      const name = `${f.subject}${f.discriminator === undefined ? '' : ` (${f.discriminator})`}`;
      const attrs = `classname="${xml(`pw-sec.${group}.${f.ruleId}`)}" name="${xml(name)}" file="${xml(f.firstSeen.file)}" line="${Math.max(1, f.firstSeen.line)}" time="0"`;
      let child: string;
      if (f.classification === 'new' && f.blocking) {
        child = `<failure type="${xml(f.ruleId)}" message="${xml(`${f.severity}/${f.confidence}: ${f.message}`)}">${xml(body(f, byId.get(f.ruleId)))}</failure>`;
        f1 += 1;
      } else if (f.classification === 'expired' && options.failOnExpired) {
        child = `<failure type="baseline-expired" message="${xml(`baseline entry expired on ${f.baseline?.until ?? '?'}: ${f.message}`)}">${xml(body(f, byId.get(f.ruleId)))}</failure>`;
        f1 += 1;
      } else if (accepted) {
        child = `<skipped message="${xml(`baseline: ${f.classification}${f.baseline?.note ? `; ${f.baseline.note}` : ''}`)}"/>`;
        s1 += 1;
      } else {
        child = `<system-out>${xml(body(f, byId.get(f.ruleId)))}</system-out>`;
      }
      cases.push(`    <testcase ${attrs}>\n      ${child}\n    </testcase>`);
    }
    if (cases.length === 0) continue;
    total += cases.length;
    failures += f1;
    skipped += s1;
    suites.push(
      `  <testsuite name="${group}" tests="${cases.length}" failures="${f1}" errors="0" skipped="${s1}" time="0">\n${cases.join('\n')}\n  </testsuite>`,
    );
  }

  if (total === 0) {
    // CI tools complain about an empty report (09-REQ-13).
    suites.push(
      '  <testsuite name="pw-sec" tests="1" failures="0" errors="0" skipped="0" time="0">\n    <testcase classname="pw-sec" name="no findings" time="0"/>\n  </testsuite>',
    );
    total = 1;
  }
  return `<?xml version="1.0" encoding="UTF-8"?>\n<testsuites name="pw-sec" tests="${total}" failures="${failures}" errors="${errors}" skipped="${skipped}" time="0">\n${suites.join('\n')}\n</testsuites>\n`;
}
