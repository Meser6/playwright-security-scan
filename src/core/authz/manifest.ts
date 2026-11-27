// The catalog of the authorization tests (18-REQ-16): manifest entries like the passive rules
// (03-REQ-05), group `authz`. They are not passive rules: the collector never runs them; the
// reporter makes their findings from replays (18, chapter 7).
import type { RuleManifest } from '../manifest/rules.ts';

export const AUTHZ_TESTS = ['unauthenticated', 'horizontal', 'vertical'] as const;
export type AuthzTest = (typeof AUTHZ_TESTS)[number];

/** Rule id of each test (18-REQ-16). */
export const AUTHZ_RULE_OF: Record<AuthzTest, string> = {
  unauthenticated: 'authz.unauthenticated-access',
  horizontal: 'authz.horizontal',
  vertical: 'authz.vertical',
};

const entry = (id: string, title: string, cwe: number[]): RuleManifest => ({
  id,
  group: 'authz',
  title,
  defaultSeverity: 'high',
  defaultConfidence: 'medium',
  scope: 'endpoint',
  cwe,
  owasp: 'A01:2025',
  sources: ['browser', 'api'],
  options: {},
});

export const AUTHZ_MANIFEST: readonly RuleManifest[] = [
  entry('authz.unauthenticated-access', 'Endpoint readable without a session', [306, 862]),
  entry('authz.horizontal', "Another user's object readable (IDOR)", [639]),
  entry('authz.vertical', 'Higher-role endpoint readable by a lower role', [285]),
];

export const AUTHZ_RULE_IDS: readonly string[] = AUTHZ_MANIFEST.map((r) => r.id);

export function authzManifest(id: string): RuleManifest | undefined {
  return AUTHZ_MANIFEST.find((r) => r.id === id);
}
