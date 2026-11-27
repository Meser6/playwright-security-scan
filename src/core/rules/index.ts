// The built-in rule catalog (06, chapter 4).
import { sessionFixation, sessionInUrl } from './auth.ts';
import { BROWSER_RULES, csrfMissing, passwordFormGet, unexpectedThirdParty } from './browser.ts';
import { sensitiveCacheable } from './cache.ts';
import { broadDomain, COOKIE_RULES } from './cookie.ts';
import { cardNumberInResponse, piiInUrl } from './data-pii.ts';
import { CORS_RULES } from './cors.ts';
import { secretInAsset, tokenInStorage } from './data.ts';
import { TOKEN_RULES } from './data-tokens.ts';
import { DISCLOSURE_RULES, internalHostname, verboseErrorJson } from './disclosure.ts';
import { HEADER_RULES } from './header.ts';
import { TRANSPORT_RULES } from './transport.ts';
import type { BuiltInRule } from './types.ts';

/** Every built-in rule, in the order of 06, chapter 4. */
export const BUILT_IN_RULES: readonly BuiltInRule[] = [
  ...HEADER_RULES,
  ...COOKIE_RULES,
  ...CORS_RULES,
  ...TRANSPORT_RULES,
  ...TOKEN_RULES,
  secretInAsset,
  tokenInStorage,
  ...DISCLOSURE_RULES,
  ...BROWSER_RULES,
  // 4.13 v3 rules
  sessionFixation,
  sessionInUrl,
  sensitiveCacheable,
  csrfMissing,
  unexpectedThirdParty,
  piiInUrl,
  cardNumberInResponse,
  broadDomain,
  internalHostname,
  verboseErrorJson,
  passwordFormGet,
];

export type {
  BuiltInRule,
  Rule,
  RuleAppliesTo,
  RuleContext,
  RuleDocs,
  RuleInput,
} from './types.ts';
