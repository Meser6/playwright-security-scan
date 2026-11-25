// Reading security-baseline.json (02, chapter 5; 08-REQ-11). Hand-written checks: the package has
// no runtime dependencies (NF-06); the JSON Schema in schemas/ describes the same format.
import type { BaselineEntry, BaselineFile, Diagnostic } from '../types/index.ts';
import { SEVERITIES } from '../types/index.ts';

const STATUSES = ['accepted', 'false-positive', 'wontfix'] as const;
const DATE = /^\d{4}-\d{2}-\d{2}$/;
const ENTRY_KEYS = new Set(['ruleId', 'subject', 'severity', 'status', 'note', 'until', 'addedAt']);

export type BaselineParse =
  | { ok: true; file: BaselineFile; diagnostics: Diagnostic[] }
  | { ok: false; diagnostics: Diagnostic[] };

const error = (message: string): Diagnostic => ({
  code: 'BASELINE_INVALID',
  level: 'error',
  message,
});

/**
 * Parses the baseline file text. Unreadable JSON, a wrong schemaVersion, an invalid entry or an
 * unknown rule id is BASELINE_INVALID with the exact place (08-REQ-11). Entries of rules switched
 * off in the config are dropped with an info diagnostic; `until` on a false-positive entry is
 * BASELINE_STALE_STATUS (08-REQ-04).
 */
export function parseBaseline(
  text: string,
  path: string,
  knownRules: ReadonlySet<string>,
  enabledRules: ReadonlySet<string>,
): BaselineParse {
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch (e) {
    return {
      ok: false,
      diagnostics: [
        error(`${path}: not valid JSON (${e instanceof Error ? e.message : String(e)})`),
      ],
    };
  }
  if (typeof data !== 'object' || data === null || Array.isArray(data)) {
    return { ok: false, diagnostics: [error(`${path}: the top level must be an object`)] };
  }
  const doc = data as Record<string, unknown>;
  if (doc.schemaVersion !== 1) {
    return {
      ok: false,
      diagnostics: [
        error(`${path}: schemaVersion must be 1, found ${JSON.stringify(doc.schemaVersion)}`),
      ],
    };
  }
  const findings = doc.findings;
  if (typeof findings !== 'object' || findings === null || Array.isArray(findings)) {
    return {
      ok: false,
      diagnostics: [error(`${path}: "findings" must be an object of fingerprint → entry`)],
    };
  }
  const problems: Diagnostic[] = [];
  const notes: Diagnostic[] = [];
  const entries: Record<string, BaselineEntry> = {};
  for (const [print, raw] of Object.entries(findings as Record<string, unknown>)) {
    const at = `${path}: findings[${JSON.stringify(print)}]`;
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
      problems.push(error(`${at} must be an object`));
      continue;
    }
    const e = raw as Record<string, unknown>;
    const unknown = Object.keys(e).filter((k) => !ENTRY_KEYS.has(k));
    if (unknown.length > 0)
      problems.push(error(`${at}: unknown field ${unknown.map((k) => `"${k}"`).join(', ')}`));
    if (typeof e.ruleId !== 'string') {
      problems.push(error(`${at}.ruleId must be a string`));
      continue;
    }
    if (!knownRules.has(e.ruleId)) {
      problems.push(error(`${at}.ruleId: unknown rule "${e.ruleId}"`));
      continue;
    }
    if (typeof e.subject !== 'string') problems.push(error(`${at}.subject must be a string`));
    if (typeof e.severity !== 'string' || !(SEVERITIES as readonly string[]).includes(e.severity)) {
      problems.push(error(`${at}.severity must be one of ${SEVERITIES.join(', ')}`));
    }
    if (typeof e.status !== 'string' || !(STATUSES as readonly string[]).includes(e.status)) {
      problems.push(error(`${at}.status must be one of ${STATUSES.join(', ')}`));
    }
    if (e.note !== undefined && typeof e.note !== 'string')
      problems.push(error(`${at}.note must be a string`));
    if (e.until !== undefined && (typeof e.until !== 'string' || !DATE.test(e.until))) {
      problems.push(error(`${at}.until must be a date YYYY-MM-DD`));
    }
    if (typeof e.addedAt !== 'string' || !DATE.test(e.addedAt))
      problems.push(error(`${at}.addedAt must be a date YYYY-MM-DD`));
    if (e.status === 'wontfix' && (typeof e.note !== 'string' || e.note.trim() === '')) {
      problems.push(error(`${at}: a wontfix entry needs a "note" (02-REQ-02)`));
    }
    if (!enabledRules.has(e.ruleId)) {
      notes.push({
        code: 'BASELINE_RULE_OFF',
        level: 'info',
        message: `${at}: rule ${e.ruleId} is off in the config; the entry is kept but not used`,
      });
    }
    if (e.status === 'false-positive' && e.until !== undefined) {
      notes.push({
        code: 'BASELINE_STALE_STATUS',
        level: 'warn',
        message: `${at}: "until" is ignored on a false-positive entry; false positives do not expire`,
      });
    }
    entries[print] = e as unknown as BaselineEntry;
  }
  if (problems.length > 0) return { ok: false, diagnostics: problems };
  const file: BaselineFile = { schemaVersion: 1, findings: entries };
  if (typeof doc.generatedBy === 'string') file.generatedBy = doc.generatedBy;
  if (typeof doc.env === 'string') file.env = doc.env;
  return { ok: true, file, diagnostics: notes };
}
