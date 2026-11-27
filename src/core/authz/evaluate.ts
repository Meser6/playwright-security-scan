// Evaluation of the replays (18-REQ-15…17, 18-REQ-20): findings, the role matrix and the pairs
// that passed, with the knowledge of the whole run (public keys, roles that got the endpoint). The
// reporter without shards and the shard merge both evaluate here.
import type { ResolvedSecurityConfig } from '../config/index.ts';
import { fingerprintOf, toFinding } from '../fingerprint/index.ts';
import type { AuthzSummary, Confidence, Coverage, Finding, RawFinding } from '../types/index.ts';
import { AUTHZ_RULE_OF } from './manifest.ts';
import type { AuthzTest } from './manifest.ts';
import { ANONYMOUS } from './plan.ts';
import type { AuthzRunData, ReplayResult } from './types.ts';

export interface AuthzEvaluation {
  findings: Finding[];
  summary: AuthzSummary;
  /** Fingerprints whose role pair was replayed and denied or answered differently (18-REQ-17). */
  passed: Set<string>;
}

type MatrixRow = AuthzSummary['matrix'][number];

const RESULT_RANK: Record<MatrixRow['result'], number> = {
  bypassed: 4,
  different: 3,
  enforced: 2,
  public: 1,
  skipped: 0,
};

/** Fingerprint of a replay pair (18-REQ-16). */
export function authzFingerprint(
  r: Pick<ReplayResult, 'test' | 'endpointKey' | 'fromRole' | 'asRole'>,
): string {
  return fingerprintOf({
    ruleId: AUTHZ_RULE_OF[r.test],
    scope: 'endpoint',
    subject: r.endpointKey,
    discriminator: `${r.fromRole}->${r.asRole}`,
  });
}

const asText = (r: ReplayResult): string =>
  r.asRole === ANONYMOUS
    ? 'without a session'
    : r.asProject !== null && r.asProject !== r.asRole
      ? `as ${r.asProject} (role ${r.asRole})`
      : `as ${r.asRole}`;

function message(r: ReplayResult): string {
  const key = r.endpointKey;
  switch (r.test) {
    case 'unauthenticated':
      return `${key} of ${r.fromRole} answered like for the logged-in user when replayed without a session.`;
    case 'horizontal':
      return `${key} answered ${r.asProject ?? r.asRole} with the object of another user of role ${r.fromRole} (IDOR).`;
    default:
      return `${key} of role ${r.fromRole} answered role ${r.asRole} like role ${r.fromRole}, although ${r.asRole} never got it in the tests.`;
  }
}

function confidenceOf(r: ReplayResult, base: Confidence): Confidence {
  if (r.kind === 'other') return 'low';
  if (r.markers && r.test !== 'vertical') return 'high';
  return base;
}

/**
 * The result of a row with the knowledge of the whole run (18-REQ-20): a key seen without
 * credentials is public for the unauthenticated and the horizontal test; a role that got the key
 * itself is no vertical test. Null: the row is no test at all.
 */
export function judged(
  r: ReplayResult,
  observed: NonNullable<Coverage['authzObserved']>,
): ReplayResult | null {
  const seen = observed[r.endpointKey];
  if ((r.test === 'unauthenticated' || r.test === 'horizontal') && seen?.public === true) {
    return { ...r, result: 'public' };
  }
  if (r.test === 'vertical' && seen?.roles.includes(r.asRole) === true) return null;
  return r;
}

/** Findings, matrix and passed pairs of the replays of a run (18, chapters 7 and 8). */
export function evaluateAuthz(
  data: AuthzRunData,
  observed: NonNullable<Coverage['authzObserved']>,
  config: ResolvedSecurityConfig,
): AuthzEvaluation {
  const findings: Finding[] = [];
  const rows = new Map<string, MatrixRow>();
  const skipped: Record<string, number> = {};
  const outcomes = new Map<string, { similar: boolean; passed: boolean }>();
  let replays = 0;
  for (const raw of data.results) {
    const r = judged(raw, observed);
    if (r === null) continue;
    const ruleId = AUTHZ_RULE_OF[r.test as AuthzTest];
    const rule = config.rules[ruleId];
    if (rule?.enabled === false) continue;
    if (r.status !== undefined || r.reason === 'replay-failed') replays += 1;
    if (r.result === 'skipped')
      skipped[r.reason ?? 'skipped'] = (skipped[r.reason ?? 'skipped'] ?? 0) + 1;
    const fingerprint = authzFingerprint(r);
    const o = outcomes.get(fingerprint) ?? { similar: false, passed: false };
    if (r.result === 'similar') o.similar = true;
    if (r.result === 'denied' || r.result === 'different') o.passed = true;
    outcomes.set(fingerprint, o);
    if (r.result === 'similar') {
      const raw: RawFinding = {
        ruleId,
        severity: rule?.severity ?? 'high',
        confidence: confidenceOf(r, rule?.confidence ?? 'medium'),
        scope: 'endpoint',
        subject: r.endpointKey,
        discriminator: `${r.fromRole}->${r.asRole}`,
        location: { origin: r.origin, endpointKey: r.endpointKey },
        evidence: [
          {
            kind: 'replay',
            snippet: `status ${String(r.originalStatus)} → ${String(r.status ?? 0)}, similarity ${(r.similarity ?? 0).toFixed(2)}, replayed ${asText(r)}${r.markers ? ', identifier of the original user in the answer' : ''}`,
          },
        ],
        message: message(r),
      };
      findings.push(toFinding(raw, r.context, r.source));
    }
    const row: MatrixRow = {
      endpointKey: r.endpointKey,
      from: r.fromRole,
      as: r.asRole,
      result: r.result === 'similar' ? 'bypassed' : r.result === 'denied' ? 'enforced' : r.result,
      ...(r.reason === undefined ? {} : { reason: r.reason }),
      ...(r.similarity === undefined ? {} : { similarity: r.similarity }),
      ...(r.result === 'similar' ? { fingerprint } : {}),
    };
    const id = `${row.endpointKey}\u0000${row.from}\u0000${row.as}\u0000${r.test}`;
    const current = rows.get(id);
    if (current === undefined || RESULT_RANK[row.result] > RESULT_RANK[current.result])
      rows.set(id, row);
  }
  for (const note of data.notes) skipped[note] = (skipped[note] ?? 0) + 1;
  const passed = new Set(
    [...outcomes].filter(([, o]) => o.passed && !o.similar).map(([fingerprint]) => fingerprint),
  );
  const matrix = [...rows.values()].sort((a, b) =>
    a.endpointKey !== b.endpointKey
      ? a.endpointKey < b.endpointKey
        ? -1
        : 1
      : `${a.from}->${a.as}` < `${b.from}->${b.as}`
        ? -1
        : 1,
  );
  return {
    findings,
    passed,
    summary: {
      roles: data.roles.map((r) => ({ name: r.name, projects: [...r.projects], level: r.level })),
      templates: data.templates,
      replays,
      budget: { ...data.budget },
      skipped: Object.fromEntries(
        Object.keys(skipped)
          .sort()
          .map((k) => [k, skipped[k] as number]),
      ),
      matrix,
    },
  };
}

/** Run data of several shards as one (18-REQ-20): budgets and templates are summed. */
export function combineAuthz(parts: readonly (AuthzRunData | null)[]): AuthzRunData | null {
  const list = parts.filter((p): p is AuthzRunData => p !== null);
  if (list.length === 0) return null;
  const roles = new Map<string, AuthzRunData['roles'][number]>();
  for (const part of list) for (const r of part.roles) if (!roles.has(r.name)) roles.set(r.name, r);
  return {
    roles: [...roles.values()],
    templates: list.reduce((n, p) => n + p.templates, 0),
    budget: {
      maxRequests: list.reduce((n, p) => n + p.budget.maxRequests, 0),
      used: list.reduce((n, p) => n + p.budget.used, 0),
      exceeded: list.some((p) => p.budget.exceeded),
    },
    results: list.flatMap((p) => p.results),
    notes: [...new Set(list.flatMap((p) => p.notes))].sort(),
  };
}
