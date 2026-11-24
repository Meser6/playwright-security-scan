/** Entry point `playwright-security-scan/config` (01, chapter 5). */
export { defineSecurityConfig, withSecurity } from '../config/with-security.ts';
export { ConfigError } from '../core/config/index.ts';
export type {
  ConfigIssue,
  Preset,
  RuleSetting,
  SecurityConfigInput,
} from '../core/config/index.ts';
export { VERSION } from '../version.ts';
