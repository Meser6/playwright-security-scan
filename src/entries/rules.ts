/**
 * Entry point `playwright-security-scan/rules` (01, chapter 5; 16-REQ-01): defineRule(), the
 * types of the rule input and findings, and pure helpers for custom rules. Imports neither
 * Playwright nor Node, so a rule can be unit-tested in any runner.
 *
 * @experimental The custom rules API may change in 0.x releases; it follows semver from 1.0.0
 * (16-REQ-14).
 * @packageDocumentation
 */
import { RULE_IDS } from '../core/manifest/rules.ts';
import type { Header, ResponseRecord } from '../core/types/index.ts';

export { VERSION } from '../version.ts';
export { defineRule } from '../core/custom/define.ts';
export type {
  CustomFinding,
  CustomRuleAppliesTo,
  CustomRuleDocs,
  Rule,
  RuleDefinition,
  RuleInput,
} from '../core/custom/define.ts';
export type { RuleContext } from '../core/rules/types.ts';
export type { Redactor } from '../core/fingerprint/index.ts';
export type {
  BrowserEvent,
  BrowserEventKind,
  Confidence,
  CookieView,
  Evidence,
  FindingScope,
  Header,
  Location,
  RawFinding,
  ResponseRecord,
  Severity,
  Source,
  TestContextRef,
} from '../core/types/index.ts';
export { parseSetCookie } from '../core/rules/cookies.ts';
export type { ParsedCookie } from '../core/rules/cookies.ts';
export { decodeJwt } from '../core/patterns/jwt.ts';
export type { DecodedJwt } from '../core/patterns/jwt.ts';

/**
 * Values of every header `name` (any case) of the response, or of the request with
 * `side: 'request'`.
 * @experimental
 */
export function getHeaders(
  record: Pick<ResponseRecord, 'requestHeaders' | 'responseHeaders'>,
  name: string,
  side: 'response' | 'request' = 'response',
): string[] {
  const lower = name.toLowerCase();
  const list: readonly Header[] =
    side === 'request' ? record.requestHeaders : record.responseHeaders;
  return list.filter((h) => h.name.toLowerCase() === lower).map((h) => h.value);
}

/**
 * Value of the first response header `name` (any case), or undefined.
 * @experimental
 */
export function getHeader(
  record: Pick<ResponseRecord, 'requestHeaders' | 'responseHeaders'>,
  name: string,
): string | undefined {
  return getHeaders(record, name)[0];
}

/** Ids of the built-in rules, e.g. to test that a custom rule does not collide. @experimental */
export const builtinRuleIds: readonly string[] = Object.freeze([...RULE_IDS]);
