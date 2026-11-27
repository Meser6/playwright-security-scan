// The rules of a run: the built-in catalog, then the custom rules in the order of rules.custom
// (16-REQ-07).
import { zapRulesOf } from '../attack/rules.ts';
import { AUTHZ_RULES } from '../authz/rules.ts';
import type { AttackSummary } from '../types/index.ts';
import type { ResolvedSecurityConfig } from '../config/index.ts';
import { adaptCustomRule } from '../custom/adapt.ts';
import type { Rule as CustomRule } from '../custom/define.ts';
import { BUILT_IN_RULES } from './index.ts';
import type { BuiltInRule } from './types.ts';

const adapted = new WeakMap<CustomRule, BuiltInRule>();

/** The adapted form of a custom rule, made once per rule object. */
function adapt(rule: CustomRule): BuiltInRule {
  let found = adapted.get(rule);
  if (found === undefined) {
    found = adaptCustomRule(rule);
    adapted.set(rule, found);
  }
  return found;
}

/** Built-in and custom rules of a resolved config. */
export function rulesOf(
  config: Pick<ResolvedSecurityConfig, 'customRules'>,
): readonly BuiltInRule[] {
  if (config.customRules.length === 0) return BUILT_IN_RULES;
  return [...BUILT_IN_RULES, ...config.customRules.map(adapt)];
}

/**
 * The rules the reports describe: those of rulesOf() and, with authz.enabled, the authorization
 * tests (18-REQ-16, 18-REQ-21).
 */
export function reportRulesOf(
  config: Pick<ResolvedSecurityConfig, 'customRules' | 'authz'>,
  attack?: AttackSummary | null,
): readonly BuiltInRule[] {
  const rules = rulesOf(config);
  // zap.* rules of an attack run (19-REQ-10): described by the alerts of the run.
  return [...rules, ...(config.authz.enabled ? AUTHZ_RULES : []), ...zapRulesOf(attack)];
}
