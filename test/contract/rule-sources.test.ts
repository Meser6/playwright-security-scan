// 15-REQ-08: the sources each rule declares match the normative table of 15, chapter 5.
import { describe, expect, test } from 'vitest';
import { RULE_IDS, RULE_MANIFEST } from '../../src/core/manifest/rules.ts';
import { BUILT_IN_RULES } from '../../src/core/rules/index.ts';

/** Rules that do NOT apply to the api source (15, chapter 5); every other rule applies to both. */
const BROWSER_ONLY = [
  'header.csp-missing',
  'header.csp-unsafe',
  'header.csp-missing-directives',
  'header.csp-report-only',
  'header.clickjacking',
  'header.referrer-policy-unsafe',
  'header.permissions-policy-missing',
  'header.coop-missing',
  'transport.mixed-content',
  'transport.form-to-http',
  'transport.weak-tls',
  'data.token-in-storage',
  'disclosure.source-map',
  'browser.csp-violation',
  'asset.sri-missing',
  'browser.reflected-param',
  // v3 (15 v0.3, chapter 5)
  'auth.session-fixation',
  'browser.csrf-missing',
  'asset.unexpected-third-party',
  'browser.password-form-get',
];

describe('15-REQ-08 rule sources follow the table of 15, chapter 5', () => {
  test.each(RULE_MANIFEST.map((r) => [r.id, r.sources] as const))('%s', (id, sources) => {
    expect(sources).toEqual(BROWSER_ONLY.includes(id) ? ['browser'] : ['browser', 'api']);
  });

  test('the catalog implements every rule of the manifest, in its order', () => {
    expect(BUILT_IN_RULES.map((r) => r.id)).toEqual(RULE_IDS);
  });
});
