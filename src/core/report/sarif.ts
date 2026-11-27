// SARIF 2.1.0 (09, chapter 5). Pure: the rule catalog and the report come in, a JSON value goes out.
import { sha256 } from '../hash/index.ts';
import type { BuiltInRule } from '../rules/index.ts';
import type { ClassifiedFinding, RunReport, Severity } from '../types/index.ts';

export const REPO_URL = 'https://github.com/Meser6/playwright-security-scan';

/** GitHub code scanning reads security-severity to classify alerts (09-REQ-06). */
export const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: '9.5',
  high: '8.0',
  medium: '5.5',
  low: '3.0',
  info: '0.0',
};

const LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};

export function ruleHelpMarkdown(rule: BuiltInRule): string {
  return [
    `**Why.** ${rule.docs.why}`,
    '',
    '**Fix.**',
    '',
    rule.docs.fix,
    '',
    `**False positives.** ${rule.docs.falsePositives}`,
  ].join('\n');
}

function result(f: ClassifiedFinding, ruleIndex: number): Record<string, unknown> {
  const where =
    f.location.endpointKey !== undefined && f.location.endpointKey !== f.subject
      ? ` (${f.location.endpointKey})`
      : '';
  const out: Record<string, unknown> = {
    ruleId: f.ruleId,
    ruleIndex,
    level: LEVEL[f.severity],
    message: { text: `${f.message} Subject: ${f.subject}${where}.` },
    // The test that first saw the finding is the anchor in the repository (09-REQ-07).
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: f.firstSeen.file, uriBaseId: '%SRCROOT%' },
          region: { startLine: Math.max(1, f.firstSeen.line) },
        },
        message: { text: `first seen in: ${f.firstSeen.titlePath.join(' › ')}` },
      },
    ],
    // Stable across runs and line moves (09-REQ-08).
    partialFingerprints: { primaryLocationLineHash: sha256(f.fingerprint) },
    properties: {
      fingerprint: f.fingerprint,
      classification: f.classification,
      severity: f.severity,
      confidence: f.confidence,
      subject: f.subject,
      sources: f.sources,
      occurrences: f.occurrences,
      tests: f.tests.length,
    },
  };
  if (f.classification !== 'new' && f.classification !== 'expired') {
    out.suppressions = [
      { kind: 'external', justification: f.baseline?.note ?? `baseline: ${f.classification}` },
    ];
  }
  return out;
}

/**
 * The SARIF log of a run (09-REQ-06 … 09-REQ-09): one run, the catalog as tool.driver.rules, new
 * and expired findings as results; accepted ones as suppressed results when `includeAccepted`.
 */
export function buildSarif(
  report: RunReport,
  rules: readonly BuiltInRule[],
  options: { version: string; includeAccepted: boolean },
): Record<string, unknown> {
  const index = new Map(rules.map((r, i) => [r.id, i]));
  const results = report.findings
    .filter(
      (f) =>
        options.includeAccepted || f.classification === 'new' || f.classification === 'expired',
    )
    .map((f) => result(f, index.get(f.ruleId) ?? -1))
    .filter((r) => (r.ruleIndex as number) >= 0);
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'playwright-security-scan',
            version: options.version,
            semanticVersion: options.version,
            informationUri: REPO_URL,
            rules: rules.map((r) => ({
              id: r.id,
              name: r.docs.title.replace(/[^A-Za-z0-9]+(.)?/g, (_m, c: string | undefined) =>
                (c ?? '').toUpperCase(),
              ),
              shortDescription: { text: r.docs.title },
              fullDescription: { text: r.docs.why },
              help: {
                text: `${r.docs.why}\n\n${r.docs.fix}\n\n${r.docs.falsePositives}`,
                markdown: ruleHelpMarkdown(r),
              },
              helpUri: `${REPO_URL}/blob/main/docs/rules/${r.id}.md`,
              defaultConfiguration: { level: LEVEL[r.manifest.defaultSeverity] },
              properties: {
                tags: [
                  'security',
                  ...r.manifest.cwe.map((n) => `CWE-${n}`),
                  ...(r.manifest.owasp === undefined ? [] : [`OWASP-${r.manifest.owasp}`]),
                ],
                'security-severity': SECURITY_SEVERITY[r.manifest.defaultSeverity],
                precision:
                  r.manifest.defaultConfidence === 'high'
                    ? 'high'
                    : r.manifest.defaultConfidence === 'medium'
                      ? 'medium'
                      : 'low',
              },
            })),
          },
        },
        // GitHub takes the part before the last "/" as the category: pw-sec (D-17).
        automationDetails: { id: `pw-sec/${report.runId}` },
        results,
        properties: {
          outcome: report.outcome.name,
          mode: report.mode,
        },
      },
    ],
  };
}
