// The rule interface (06, chapter 2). Rules are pure (06-REQ-01): no state between calls, no I/O.
import type { Redactor } from '../fingerprint/index.ts';
import { ruleManifest as ruleManifestById } from '../manifest/rules.ts';
import type { RuleManifest } from '../manifest/rules.ts';
import type {
  BrowserEvent,
  BrowserEventKind,
  Confidence,
  RawFinding,
  ResponseRecord,
  Severity,
  Source,
  TestTraffic,
} from '../types/index.ts';

export interface RuleContext {
  /** Rule options after merging the config into the defaults (03-REQ-03). */
  options: Record<string, unknown>;
  /** Severity and confidence from the config and preset; rules lower them only when documented. */
  severity: Severity;
  confidence: Confidence;
  /** The record or document is on localhost (05-REQ-06): transport rules are advisory. */
  localDev: boolean;
  isHttps: boolean;
  /** Whether an origin is in the scan scope (05-REQ-04). */
  inScope(origin: string): boolean;
  /** Redaction of this run (07-REQ-12). */
  redact: Redactor;
}

export interface RuleAppliesTo {
  /** request.resourceType() values; 'api' for APIRequestContext records. Unset: any. */
  resourceTypes?: string[];
  /** Traffic sources; unset: both (15, chapter 5). */
  sources?: Source[];
  /** Browser events the rule checks; then records only with `records: true`. */
  events?: BrowserEventKind[];
  /** With `events`: the rule also checks records. */
  records?: boolean;
  /** Also gets out-of-scope records, without body (05-REQ-05: mixed content). */
  outOfScope?: boolean;
  /** Gets the end-of-test input TestTraffic, once per test (06, chapter 4.13.1). */
  testEnd?: boolean;
}

/** What a rule checks: a response record, a browser event or the end-of-test traffic. */
export type RuleInput = ResponseRecord | BrowserEvent | TestTraffic;

export interface RuleDocs {
  title: string;
  why: string;
  /** With examples for nginx, Express and Spring (06-AC-03). */
  fix: string;
  falsePositives: string;
  /** Docs link of a custom rule (16-REQ-12); built-in rules link to docs/rules/<id>.md. */
  url?: string;
}

export interface Rule {
  id: string;
  appliesTo: RuleAppliesTo;
  /** Resource types whose body the rule reads (05-REQ-10); unset: none. */
  needsBody?: string[];
  check(input: RuleInput, ctx: RuleContext): RawFinding[];
  docs: RuleDocs;
}

/** Where the docs of a rule are: docs/rules/<id>.md, or docs.url of a custom rule (16-REQ-12). */
export function ruleDocsUrl(rule: BuiltInRule, repoUrl: string): string | undefined {
  if (rule.manifest.group === 'custom') return rule.docs.url;
  return `${repoUrl}/blob/main/docs/rules/${rule.id}.md`;
}

/** A rule with its manifest entry. */
export type BuiltInRule = Rule & { manifest: RuleManifest };

/** A finding of `rule` with the severity and confidence from the context. */
export function finding(
  ctx: RuleContext,
  manifest: Pick<RuleManifest, 'id' | 'scope'>,
  fields: Omit<RawFinding, 'ruleId' | 'scope' | 'severity' | 'confidence'> &
    Partial<Pick<RawFinding, 'severity' | 'confidence' | 'scope'>>,
): RawFinding {
  return {
    ruleId: manifest.id,
    scope: fields.scope ?? manifest.scope,
    severity: fields.severity ?? ctx.severity,
    confidence: fields.confidence ?? ctx.confidence,
    ...fields,
  };
}

/** Value of the first header named `name` (lowercase), or undefined. */
export function header(
  headers: readonly { name: string; value: string }[],
  name: string,
): string | undefined {
  return headers.find((h) => h.name === name)?.value;
}

/** Values of every header named `name` (lowercase). */
export function headers(list: readonly { name: string; value: string }[], name: string): string[] {
  return list.filter((h) => h.name === name).map((h) => h.value);
}

/** Whether a record is a response the rule may judge as JSON. */
export function isJson(contentType: string | undefined): boolean {
  if (contentType === undefined) return false;
  const type = contentType.split(';')[0]?.trim().toLowerCase() ?? '';
  return type === 'application/json' || type.endsWith('+json');
}

/** The manifest entry of a built-in rule; throws for an unknown id (a programming error). */
export function manifestOf(id: string): RuleManifest {
  const found = ruleManifestById(id);
  if (found === undefined) throw new Error(`no manifest entry for ${id}`);
  return found;
}

/** Transport rules are advisory on local origins (05-REQ-06). */
export function transportConfidence(ctx: RuleContext): Confidence {
  return ctx.localDev ? 'low' : ctx.confidence;
}
