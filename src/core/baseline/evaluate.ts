// Classification against the baseline, expiry, resolved entries and the result code (08; 00,
// chapter 11). Pure: the date of the run is a parameter.
import { domainMatchesHost } from './domain.ts';
import type {
  BaselineFile,
  ClassifiedFinding,
  Confidence,
  Coverage,
  Diagnostic,
  EntryRef,
  Finding,
  OutcomeFile,
  Severity,
} from '../types/index.ts';
import { confidenceRank, severityRank } from '../types/index.ts';

/** Days before `until` when the entry gets the "expires in N days" warning (08-REQ-03). */
export const EXPIRY_WARNING_DAYS = 14;

export interface Gate {
  minSeverity: Severity;
  minConfidence: Confidence;
  failOnExpired: boolean;
  failOnNoTraffic: boolean;
}

const DAY = 86_400_000;
const days = (from: string, to: string): number =>
  Math.round((Date.parse(`${to}T00:00:00Z`) - Date.parse(`${from}T00:00:00Z`)) / DAY);

const blocksAsNew = (f: Finding, gate: Gate): boolean =>
  severityRank(f.severity) >= severityRank(gate.minSeverity) &&
  confidenceRank(f.confidence) >= confidenceRank(gate.minConfidence);

/**
 * Classifies each finding (08, chapter 3). `today` is the run date in UTC (YYYY-MM-DD). In a
 * baseline run (`gateOn` false) nothing blocks.
 */
export function classify(
  findings: readonly Finding[],
  baseline: BaselineFile | undefined,
  gate: Gate,
  today: string,
  gateOn: boolean,
): ClassifiedFinding[] {
  return findings.map((f): ClassifiedFinding => {
    const entry = baseline?.findings[f.fingerprint];
    if (entry === undefined)
      return { ...f, classification: 'new', blocking: gateOn && blocksAsNew(f, gate) };
    const info: NonNullable<ClassifiedFinding['baseline']> = {
      status: entry.status,
      addedAt: entry.addedAt,
    };
    if (entry.note !== undefined) info.note = entry.note;
    if (entry.until !== undefined) info.until = entry.until;
    if (entry.status === 'false-positive') {
      return { ...f, classification: 'false-positive', blocking: false, baseline: info };
    }
    if (entry.until !== undefined) {
      const left = days(today, entry.until);
      if (left < 0) {
        return {
          ...f,
          classification: 'expired',
          blocking: gateOn && gate.failOnExpired,
          baseline: info,
        };
      }
      if (left <= EXPIRY_WARNING_DAYS) info.expiresInDays = left;
    }
    return { ...f, classification: entry.status, blocking: false, baseline: info };
  });
}

/** Scope and subject of a fingerprint `ruleId|scope|subject[|discriminator]`. */
export function parseFingerprint(print: string): {
  ruleId: string;
  scope: string;
  subject: string;
} {
  const [ruleId = '', scope = '', ...rest] = print.split('|');
  // A subject may itself contain "|" only in rare endpoint keys; the discriminator is last.
  const subject = rest.length > 1 ? rest.slice(0, -1).join('|') : (rest[0] ?? '');
  return { ruleId, scope, subject };
}

/**
 * Whether the run covered the scope of a baseline entry (08-REQ-05): a document of the origin, the
 * endpoint key, a response of an origin the cookie belongs to, the asset, a Web Storage scan of the
 * origin.
 */
export function covered(entrySubject: string, scope: string, coverage: Coverage): boolean {
  switch (scope) {
    case 'origin':
      return (coverage.origins[entrySubject]?.documents ?? 0) > 0;
    case 'endpoint':
      return (coverage.endpoints[entrySubject] ?? 0) > 0;
    case 'asset':
      return coverage.assets.includes(entrySubject);
    case 'storage-key': {
      const at = entrySubject.lastIndexOf('@');
      return at > 0 && coverage.storageOrigins.includes(entrySubject.slice(at + 1));
    }
    case 'cookie': {
      const at = entrySubject.lastIndexOf('@');
      if (at <= 0) return false;
      const domain = entrySubject.slice(at + 1);
      return Object.entries(coverage.origins).some(
        ([origin, c]) => c.responses > 0 && domainMatchesHost(origin, domain),
      );
    }
    default:
      return false;
  }
}

/** Baseline entries without a finding: resolved when covered, else not covered (08-REQ-05). */
export function resolveEntries(
  baseline: BaselineFile | undefined,
  findings: readonly Finding[],
  coverage: Coverage,
  enabledRules: ReadonlySet<string>,
): { resolved: EntryRef[]; notCovered: EntryRef[] } {
  const seen = new Set(findings.map((f) => f.fingerprint));
  const resolved: EntryRef[] = [];
  const notCovered: EntryRef[] = [];
  for (const [fingerprint, entry] of Object.entries(baseline?.findings ?? {}).sort(([a], [b]) =>
    a < b ? -1 : 1,
  )) {
    if (seen.has(fingerprint)) continue;
    const ref = { fingerprint, ruleId: entry.ruleId, subject: entry.subject };
    const { scope } = parseFingerprint(fingerprint);
    if (enabledRules.has(entry.ruleId) && covered(entry.subject, scope, coverage))
      resolved.push(ref);
    else notCovered.push(ref);
  }
  return { resolved, notCovered };
}

const NAMES = ['OK', 'NEW_FINDINGS', 'BASELINE_EXPIRED', 'TOOL_ERROR', 'NO_TRAFFIC'] as const;

/**
 * The result code (00, chapter 11; 08-REQ-02): TOOL_ERROR > NEW_FINDINGS > BASELINE_EXPIRED >
 * NO_TRAFFIC > OK.
 */
export function outcome(input: {
  findings: readonly ClassifiedFinding[];
  resolved: number;
  diagnostics: readonly Diagnostic[];
  testsPassed: boolean;
  responses: number;
  gate: Gate;
}): OutcomeFile {
  const newBlocking = input.findings.filter((f) => f.classification === 'new' && f.blocking).length;
  const newNonBlocking = input.findings.filter(
    (f) => f.classification === 'new' && !f.blocking,
  ).length;
  const expired = input.findings.filter((f) => f.classification === 'expired').length;
  const expiredBlocking = input.findings.filter(
    (f) => f.classification === 'expired' && f.blocking,
  ).length;
  let code: OutcomeFile['code'] = 0;
  if (input.diagnostics.some((d) => d.level === 'error')) code = 3;
  else if (newBlocking > 0) code = 1;
  else if (expiredBlocking > 0) code = 2;
  else if (input.responses === 0 && input.gate.failOnNoTraffic) code = 4;
  return {
    schemaVersion: 1,
    code,
    name: NAMES[code],
    testsPassed: input.testsPassed,
    newBlocking,
    newNonBlocking,
    expired,
    resolved: input.resolved,
  };
}

/** accepted/wontfix entries without a note when baseline.requireNote is on (08-REQ-10). */
export function missingNotes(baseline: BaselineFile | undefined): Diagnostic[] {
  const prints = Object.entries(baseline?.findings ?? {})
    .filter(
      ([, e]) => e.status !== 'false-positive' && (e.note === undefined || e.note.trim() === ''),
    )
    .map(([p]) => p)
    .sort();
  if (prints.length === 0) return [];
  return [
    {
      code: 'BASELINE_NOTE_REQUIRED',
      level: 'error',
      message: `baseline.requireNote: ${prints.length} accepted entries have no note: ${prints.slice(0, 10).join(', ')}${prints.length > 10 ? ', …' : ''}`,
    },
  ];
}
