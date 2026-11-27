// Custom rules of the user (16, ADR-0013 / D-20): defineRule() and the validation of a definition
// (16-REQ-04). Pure; loaded by the config entry, so it must not import the rule code (01-AC-01).
import { ConfigError } from '../config/errors.ts';
import type { ConfigIssue } from '../config/types.ts';
import type { RuleContext } from '../rules/types.ts';
import { CONFIDENCES, SEVERITIES } from '../types/index.ts';
import type {
  BrowserEvent,
  BrowserEventKind,
  Confidence,
  Evidence,
  FindingScope,
  Location,
  ResponseRecord,
  Severity,
  Source,
  TestTraffic,
} from '../types/index.ts';

/** Marks objects made by defineRule(); Symbol.for gives one key for the ESM and the CJS build. */
export const CUSTOM_RULE: unique symbol = Symbol.for('playwright-security-scan.custom-rule');

/** `custom.<name>` (16-REQ-03). */
export const CUSTOM_ID_PATTERN = /^custom\.[a-z0-9][a-z0-9-]{0,47}$/;
export const CUSTOM_ID_TEXT = 'custom.<name>, <name> matching [a-z0-9][a-z0-9-]{0,47}';

const SCOPES: readonly FindingScope[] = ['origin', 'endpoint', 'cookie', 'storage-key', 'asset'];
const SOURCES: readonly Source[] = ['browser', 'api'];
const EVENTS: readonly BrowserEventKind[] = ['csp-violation', 'storage', 'cookie-jar'];

/**
 * Input of a custom rule: a response record, a browser event or the end-of-test traffic
 * (06, chapters 2 and 4.13.1).
 */
export type RuleInput = ResponseRecord | BrowserEvent | TestTraffic;

/**
 * What `check` of a custom rule returns (16-REQ-02): a raw finding without `ruleId`, `severity`,
 * `confidence` and `scope`, which the package fills in from the definition and the config.
 * @experimental
 */
export interface CustomFinding {
  /** Origin, endpoint key, name@domain, storage key or normalized asset URL (07, chapter 3). */
  subject: string;
  /** Tells apart problems of one rule on one subject (07-REQ-06); never a value. */
  discriminator?: string;
  message: string;
  /** Defaults to the origin of the input. */
  location?: Partial<Location>;
  /** Redacted by the package (07-REQ-12); at most 3 per finding are kept. */
  evidence?: Evidence[];
}

/** @experimental */
export interface CustomRuleAppliesTo {
  /** Traffic sources; unset: both (15, chapter 5). */
  sources?: Source[];
  /** request.resourceType() values; 'api' for APIRequestContext records. Unset: any. */
  resourceTypes?: string[];
  /** Response records; the default unless only `events` are given. */
  records?: boolean;
  /** Browser events the rule checks. */
  events?: BrowserEventKind[];
  /** Also out-of-scope records, without body (05-REQ-05). */
  outOfScope?: boolean;
  /** The end-of-test input TestTraffic, once per test (06, chapter 4.13.1). */
  testEnd?: boolean;
}

/** @experimental */
export interface CustomRuleDocs {
  title: string;
  why: string;
  fix: string;
  falsePositives?: string;
  /** Link to the team's documentation of the rule (SARIF helpUri, "Rule docs" in HTML). */
  url?: string;
}

/**
 * Definition of a custom rule (16-REQ-02). `check` must be a pure, synchronous function
 * (06-REQ-01, 16-REQ-08).
 * @experimental
 */
export interface RuleDefinition {
  /** `custom.<name>` (16-REQ-03). */
  id: string;
  defaultSeverity: Severity;
  defaultConfidence: Confidence;
  /** What the subject is; part of the fingerprint (07-REQ-05). */
  scope: FindingScope;
  appliesTo?: CustomRuleAppliesTo;
  /** Read response bodies (05-REQ-10): true or the resource types. */
  needsBody?: boolean | string[];
  /** Option defaults, overridden in the config (`rules['custom.x'].options`). */
  options?: Record<string, unknown>;
  cwe?: number[];
  /** OWASP Top 10 2025 category, e.g. 'A02:2025'. */
  owasp?: string;
  docs: CustomRuleDocs;
  check(input: RuleInput, ctx: RuleContext): CustomFinding[];
}

/** A custom rule made by defineRule(). @experimental */
export type Rule = Readonly<RuleDefinition> & { readonly [CUSTOM_RULE]: true };

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

const isText = (v: unknown): v is string => typeof v === 'string' && v.trim() !== '';

/** The id of a value that looks like a rule, for messages. */
function label(value: unknown): string {
  return isRecord(value) && typeof value.id === 'string' ? value.id : '?';
}

/** Problems of one rule definition (16-REQ-04); `path` is where it is, e.g. "rules.custom[0]". */
export function ruleDefinitionIssues(value: unknown, path: string): ConfigIssue[] {
  const issues: ConfigIssue[] = [];
  const add = (field: string, message: string, hint?: string): void => {
    const at = field === '' ? path : `${path}.${field}`;
    issues.push({
      code: 'CONFIG_INVALID_RULE',
      path: at,
      message: `${at}: ${message}`,
      ...(hint === undefined ? {} : { hint }),
    });
  };
  if (!isRecord(value)) {
    add('', 'expected a rule made with defineRule() from playwright-security-scan/rules');
    return issues;
  }
  if (typeof value.id !== 'string') add('id', 'missing rule id');
  else if (!CUSTOM_ID_PATTERN.test(value.id)) {
    add('id', `invalid rule id ${JSON.stringify(value.id)}`, `Use ${CUSTOM_ID_TEXT}.`);
  }
  if (!(SEVERITIES as readonly unknown[]).includes(value.defaultSeverity)) {
    add('defaultSeverity', `missing or invalid, expected one of ${SEVERITIES.join(', ')}`);
  }
  if (!(CONFIDENCES as readonly unknown[]).includes(value.defaultConfidence)) {
    add('defaultConfidence', `missing or invalid, expected one of ${CONFIDENCES.join(', ')}`);
  }
  if (!(SCOPES as readonly unknown[]).includes(value.scope)) {
    add('scope', `missing or invalid, expected one of ${SCOPES.join(', ')}`);
  }
  if (typeof value.check !== 'function') add('check', 'missing check(input, ctx) function');
  if (!isRecord(value.docs)) add('docs', 'missing docs { title, why, fix }');
  else {
    for (const field of ['title', 'why', 'fix'] as const) {
      if (!isText(value.docs[field])) add(`docs.${field}`, 'missing text');
    }
    const fp = value.docs.falsePositives;
    if (fp !== undefined && typeof fp !== 'string') add('docs.falsePositives', 'expected text');
    const url = value.docs.url;
    if (url !== undefined && (typeof url !== 'string' || !/^https?:\/\/\S+$/.test(url))) {
      add('docs.url', 'expected an http(s):// address');
    }
  }
  const to = value.appliesTo;
  if (to !== undefined) {
    if (!isRecord(to)) add('appliesTo', 'expected an object');
    else {
      const known = ['sources', 'resourceTypes', 'records', 'events', 'outOfScope', 'testEnd'];
      for (const key of Object.keys(to)) {
        if (!known.includes(key)) {
          add(`appliesTo.${key}`, 'unknown field', `Allowed: ${known.join(', ')}.`);
        }
      }
      const list = (field: string, v: unknown, allowed?: readonly string[]): void => {
        if (v === undefined) return;
        if (
          !Array.isArray(v) ||
          v.some((x) => typeof x !== 'string' || (allowed !== undefined && !allowed.includes(x)))
        ) {
          add(
            `appliesTo.${field}`,
            allowed === undefined
              ? 'expected an array of strings'
              : `expected an array of ${allowed.join(', ')}`,
          );
        }
      };
      list('sources', to.sources, SOURCES);
      list('resourceTypes', to.resourceTypes);
      list('events', to.events, EVENTS);
      for (const flag of ['records', 'outOfScope', 'testEnd'] as const) {
        if (to[flag] !== undefined && typeof to[flag] !== 'boolean') {
          add(`appliesTo.${flag}`, 'expected true or false');
        }
      }
      const hasEvents = Array.isArray(to.events) && to.events.length > 0;
      if (to.records === false && !hasEvents && to.testEnd !== true) {
        add(
          'appliesTo',
          'the rule has no input: set records: true, events: [...] or testEnd: true',
        );
      }
    }
  }
  const body = value.needsBody;
  if (
    body !== undefined &&
    typeof body !== 'boolean' &&
    (!Array.isArray(body) || body.some((x) => typeof x !== 'string'))
  ) {
    add('needsBody', 'expected true, false or an array of resource types');
  }
  if (value.options !== undefined) {
    if (!isRecord(value.options)) add('options', 'expected an object');
    else {
      for (const [key, v] of Object.entries(value.options)) {
        if (typeof v === 'function' || typeof v === 'symbol') {
          add(`options.${key}`, 'expected data (string, number, boolean, array or object)');
        }
      }
    }
  }
  if (
    value.cwe !== undefined &&
    (!Array.isArray(value.cwe) || value.cwe.some((n) => !Number.isInteger(n) || n <= 0))
  ) {
    add('cwe', 'expected an array of CWE numbers');
  }
  if (value.owasp !== undefined && !isText(value.owasp)) add('owasp', 'expected text');
  return issues;
}

/** Whether `value` was made by defineRule(). */
export function isCustomRule(value: unknown): value is Rule {
  return isRecord(value) && (value as Record<symbol, unknown>)[CUSTOM_RULE] === true;
}

/** Problems of `rules.custom` (16-REQ-04): definitions, origin and duplicate ids. */
export function customRulesIssues(value: unknown, path = 'rules.custom'): ConfigIssue[] {
  if (!Array.isArray(value)) {
    return [
      {
        code: 'CONFIG_INVALID_TYPE',
        path,
        message: `${path}: expected an array of rules made with defineRule()`,
      },
    ];
  }
  const issues: ConfigIssue[] = [];
  const seen = new Set<string>();
  value.forEach((rule, i) => {
    const at = `${path}[${i}]`;
    const own = ruleDefinitionIssues(rule, at);
    issues.push(...own);
    if (own.length === 0 && !isCustomRule(rule)) {
      issues.push({
        code: 'CONFIG_INVALID_RULE',
        path: at,
        message: `${at}: rule ${label(rule)} was not made with defineRule()`,
        hint: "Wrap it: export const rule = defineRule({ ... }) from 'playwright-security-scan/rules'.",
      });
    }
    const id = label(rule);
    if (id === '?') return;
    if (seen.has(id)) {
      issues.push({
        code: 'CONFIG_DUPLICATE_RULE',
        path: at,
        message: `${at}: rule id ${id} is used twice`,
      });
    }
    seen.add(id);
  });
  return issues;
}

/**
 * Defines a custom rule (16-REQ-01). Throws a ConfigError with every problem of the definition;
 * returns a frozen rule to put into `rules.custom`.
 * @experimental The custom rules API may change in 0.x releases (16-REQ-14).
 */
export function defineRule(definition: RuleDefinition): Rule {
  const issues = ruleDefinitionIssues(definition, `defineRule(${label(definition)})`);
  if (issues.length > 0) throw new ConfigError(issues);
  const rule = {
    ...definition,
    ...(definition.appliesTo === undefined
      ? {}
      : { appliesTo: Object.freeze({ ...definition.appliesTo }) }),
    ...(definition.options === undefined
      ? {}
      : { options: Object.freeze({ ...definition.options }) }),
    docs: Object.freeze({ ...definition.docs }),
    [CUSTOM_RULE]: true as const,
  };
  return Object.freeze(rule);
}
