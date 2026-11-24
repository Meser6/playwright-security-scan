// Quality of the rule catalog on the reference app (10, chapter 3): every rule detects its own
// case (10-REQ-05, S-03), the secure mode is clean (10-REQ-04, NF-11), and no secret of the app
// reaches any output file (S-07). One Playwright run with one project per app instance.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, test } from 'vitest';
import { RULE_IDS } from '../../src/core/manifest/rules.ts';
import { APP_RULES, NOT_REPRODUCIBLE, SECRETS, startShop } from '../app/shop.ts';
import type { Shop } from '../app/shop.ts';
import { filesUnder, RUN_TIMEOUT, startHarness } from '../integration/harness.ts';
import type { Harness, ProjectRun } from '../integration/harness.ts';

/** Findings that a switch documents besides its own rule (10-REQ-05). */
const COMPANIONS: Record<string, string[]> = {
  // The partner sends an authorization header to the wildcard endpoint.
  'cors.wildcard-credentials': ['cors.wildcard-sensitive'],
  // The stack trace comes with a 500.
  'disclosure.stack-trace': ['disclosure.server-error'],
};

let harness: Harness;
let run: ProjectRun;
const shops: Shop[] = [];

beforeAll(async () => {
  harness = await startHarness();
  const instances: { name: string; url: string; partner: string }[] = [];
  for (const name of ['secure', ...APP_RULES]) {
    const shop = await startShop(name === 'secure' ? [] : [name]);
    shops.push(shop);
    instances.push({
      name,
      url: name === 'transport.cleartext' ? shop.httpUrl : shop.url,
      partner: shop.partnerUrl,
    });
  }
  run = await harness.run(harness.copy('detect'), {
    env: { PW_SEC_MODE: 'scan', APP_INSTANCES: JSON.stringify(instances) },
  });
}, RUN_TIMEOUT * 2);

afterAll(async () => {
  await Promise.all(shops.map((s) => s.close()));
  await harness?.close();
});

const findingsOf = (project: string) =>
  run.results.filter((r) => r.project === project).flatMap((r) => r.attachment?.findings ?? []);
const ruleIdsOf = (project: string): string[] =>
  [...new Set(findingsOf(project).map((f) => f.ruleId))].sort();

describe('rule quality on the reference app (10, chapter 3)', () => {
  test('every test of every instance passes', () => {
    expect(run.results.length, run.output.slice(-2000)).toBe(12 * (APP_RULES.length + 1));
    expect(
      run.results.filter((r) => r.status !== 'passed').map((r) => `${r.project}: ${r.title}`),
    ).toEqual([]);
  });

  test('06-AC-02 the secure app has no finding of severity low or above (NF-11, 10-REQ-04), even in the strict preset', () => {
    const findings = findingsOf('secure');
    expect(findings.map((f) => `${f.fingerprint} (${f.severity})`)).toEqual([]);
  });

  test('every rule is reproducible by the app, except those documented as not reproducible', () => {
    expect([...APP_RULES, ...Object.keys(NOT_REPRODUCIBLE)].sort()).toEqual([...RULE_IDS].sort());
  });

  describe('06-AC-01 S-03 every switch gives findings of its rule and only documented companions (10-REQ-05)', () => {
    test.each(APP_RULES.map((rule) => [rule]))('%s', (rule) => {
      const secure = new Set(ruleIdsOf('secure'));
      const extra = ruleIdsOf(rule).filter((id) => !secure.has(id));
      expect(extra).toContain(rule);
      expect(extra.filter((id) => id !== rule)).toEqual(COMPANIONS[rule] ?? []);
    });
  });

  test('07-AC-03 S-07 09-AC-03 no secret of the app is in any output file or attachment', () => {
    const files = [
      ...filesUnder(join(run.dir, 'reports')),
      ...filesUnder(join(run.dir, 'test-results')),
      join(run.dir, 'results.json'),
    ];
    expect(files.length).toBeGreaterThan(2);
    for (const file of files) {
      const text = readFileSync(file, 'latin1');
      for (const [name, secret] of Object.entries(SECRETS)) {
        expect(text.includes(secret), `${name} in ${file}`).toBe(false);
      }
    }
  });
});
