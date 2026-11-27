// A custom rule as the rule loop sees it (16-REQ-07, 16-REQ-10): the same Rule + manifest shape as
// a built-in rule, with `check` filling in what the package owns (id, severity, confidence, scope).
import type { RuleManifest } from '../manifest/rules.ts';
import type { BuiltInRule, RuleAppliesTo, RuleContext } from '../rules/types.ts';
import type {
  BrowserEvent,
  Evidence,
  Location,
  RawFinding,
  ResponseRecord,
  Source,
} from '../types/index.ts';
import type { Rule, RuleInput } from './define.ts';

/** Resource types whose body `needsBody: true` reads when the rule names none (16, chapter 12a). */
export const DEFAULT_BODY_TYPES: readonly string[] = [
  'document',
  'script',
  'stylesheet',
  'xhr',
  'fetch',
  'api',
];

const EVIDENCE_KINDS: readonly Evidence['kind'][] = [
  'header',
  'cookie',
  'body',
  'url',
  'storage',
  'event',
];

/** `check` of a custom rule returned a promise (16-REQ-08). */
export class CustomRuleAsyncError extends Error {
  constructor(id: string) {
    super(`rule ${id}: check() returned a promise; custom rules must be synchronous`);
    this.name = 'CustomRuleAsyncError';
  }
}

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

function isPromiseLike(v: unknown): v is PromiseLike<unknown> {
  return (
    (typeof v === 'object' || typeof v === 'function') &&
    v !== null &&
    typeof (v as { then?: unknown }).then === 'function'
  );
}

/** The origin of a rule input, the default of `location.origin`. */
function inputOrigin(input: ResponseRecord | BrowserEvent): string {
  if (input.kind === 'response' || input.kind === 'storage') return input.origin;
  if (input.kind === 'csp-violation') return input.documentOrigin;
  return input.cookies[0]?.origin ?? '';
}

function toEvidence(value: unknown, ctx: RuleContext, at: string): Evidence {
  if (!isRecord(value) || !EVIDENCE_KINDS.includes(value.kind as Evidence['kind'])) {
    throw new Error(`${at}: expected { kind: ${EVIDENCE_KINDS.join(' | ')}, snippet }`);
  }
  if (typeof value.snippet !== 'string') throw new Error(`${at}.snippet must be a string`);
  const kind = value.kind as Evidence['kind'];
  const name = typeof value.name === 'string' && value.name !== '' ? value.name : undefined;
  // Header evidence gets the header redaction (07-REQ-13) before the final filter (07-REQ-12).
  const snippet =
    kind === 'header' && name !== undefined
      ? ctx.redact.header(name, value.snippet)
      : value.snippet;
  return { kind, ...(name === undefined ? {} : { name }), snippet };
}

/** Only the fields of Location (02, chapter 4), with the defaults of the input. */
function toLocation(
  value: Record<string, unknown>,
  input: ResponseRecord | BrowserEvent,
): Location {
  const text = (key: string): string | undefined =>
    typeof value[key] === 'string' && value[key] !== '' ? value[key] : undefined;
  const endpointKey =
    text('endpointKey') ?? (input.kind === 'response' ? input.endpointKey : undefined);
  const param = text('param');
  const header = text('header');
  return {
    origin: text('origin') ?? inputOrigin(input),
    ...(endpointKey === undefined ? {} : { endpointKey }),
    ...(param === undefined ? {} : { param }),
    ...(header === undefined ? {} : { header }),
  };
}

/** Wraps a custom rule into the shape of a built-in rule (16-REQ-02, 16-REQ-07). */
export function adaptCustomRule(rule: Rule): BuiltInRule {
  const to = rule.appliesTo ?? {};
  const events = to.events ?? [];
  const records =
    to.records ??
    (events.length === 0 || to.resourceTypes !== undefined || to.sources !== undefined);
  const appliesTo: RuleAppliesTo = {
    ...(to.resourceTypes === undefined ? {} : { resourceTypes: [...to.resourceTypes] }),
    ...(to.sources === undefined ? {} : { sources: [...to.sources] }),
    ...(events.length === 0 ? {} : { events: [...events], records }),
    ...(to.outOfScope === true ? { outOfScope: true } : {}),
  };
  const sources: Source[] = to.sources === undefined ? ['browser', 'api'] : [...to.sources];
  const manifest: RuleManifest = {
    id: rule.id,
    group: 'custom',
    title: rule.docs.title,
    defaultSeverity: rule.defaultSeverity,
    defaultConfidence: rule.defaultConfidence,
    scope: rule.scope,
    cwe: [...(rule.cwe ?? [])],
    ...(rule.owasp === undefined ? {} : { owasp: rule.owasp }),
    sources,
    options: { ...(rule.options ?? {}) },
  };
  const needsBody =
    rule.needsBody === true
      ? [...(to.resourceTypes ?? DEFAULT_BODY_TYPES)]
      : Array.isArray(rule.needsBody)
        ? [...rule.needsBody]
        : undefined;
  return {
    id: rule.id,
    appliesTo,
    ...(needsBody === undefined ? {} : { needsBody }),
    manifest,
    docs: {
      title: rule.docs.title,
      why: rule.docs.why,
      fix: rule.docs.fix,
      falsePositives: rule.docs.falsePositives ?? '',
      ...(rule.docs.url === undefined ? {} : { url: rule.docs.url }),
    },
    check(input, ctx): RawFinding[] {
      const out: unknown = rule.check(input as RuleInput, ctx);
      if (isPromiseLike(out)) {
        // The rejection of a promise nobody awaits would crash the worker.
        Promise.resolve(out).catch(() => undefined);
        throw new CustomRuleAsyncError(rule.id);
      }
      if (!Array.isArray(out)) {
        throw new Error(`check() must return an array of findings, got ${typeof out}`);
      }
      return out.map((value: unknown, i): RawFinding => {
        const at = `finding ${i}`;
        if (!isRecord(value)) throw new Error(`${at}: expected an object`);
        if (typeof value.subject !== 'string' || value.subject === '') {
          throw new Error(`${at}: subject must be a non-empty string`);
        }
        if (typeof value.message !== 'string' || value.message === '') {
          throw new Error(`${at}: message must be a non-empty string`);
        }
        if (value.discriminator !== undefined && typeof value.discriminator !== 'string') {
          throw new Error(`${at}: discriminator must be a string`);
        }
        if (value.evidence !== undefined && !Array.isArray(value.evidence)) {
          throw new Error(`${at}: evidence must be an array`);
        }
        const location = isRecord(value.location) ? value.location : {};
        const evidence = (value.evidence ?? []) as unknown[];
        return {
          ruleId: rule.id,
          scope: rule.scope,
          severity: ctx.severity,
          confidence: ctx.confidence,
          subject: value.subject,
          ...(value.discriminator === undefined ? {} : { discriminator: value.discriminator }),
          location: toLocation(location, input),
          evidence: evidence.slice(0, 3).map((e, j) => toEvidence(e, ctx, `${at}.evidence[${j}]`)),
          message: value.message,
        };
      });
    },
  };
}
