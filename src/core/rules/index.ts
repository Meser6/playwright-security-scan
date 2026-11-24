// The built-in rule catalog (06). WP-08 and WP-09 add the remaining rules.
import { secretInAsset, tokenInStorage } from './data.ts';
import { xctoMissing } from './header.ts';
import type { BuiltInRule } from './types.ts';

export const BUILT_IN_RULES: readonly BuiltInRule[] = [xctoMissing, secretInAsset, tokenInStorage];

export type { BuiltInRule, Rule, RuleAppliesTo, RuleContext, RuleDocs } from './types.ts';
