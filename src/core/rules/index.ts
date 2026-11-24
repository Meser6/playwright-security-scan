// The built-in rule catalog (06). WP-09 adds the remaining groups.
import { COOKIE_RULES } from './cookie.ts';
import { CORS_RULES } from './cors.ts';
import { secretInAsset, tokenInStorage } from './data.ts';
import { HEADER_RULES } from './header.ts';
import { TRANSPORT_RULES } from './transport.ts';
import type { BuiltInRule } from './types.ts';

export const BUILT_IN_RULES: readonly BuiltInRule[] = [
  ...HEADER_RULES,
  ...COOKIE_RULES,
  ...CORS_RULES,
  ...TRANSPORT_RULES,
  secretInAsset,
  tokenInStorage,
];

export type { BuiltInRule, Rule, RuleAppliesTo, RuleContext, RuleDocs } from './types.ts';
