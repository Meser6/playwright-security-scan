// The reference app (10, chapter 3): its tests pass in the secure mode and with every switch.
import { afterAll, beforeAll, describe, expect, test } from 'vitest';
import { APP_RULES, startShop } from '../app/shop.ts';
import type { Shop } from '../app/shop.ts';
import { RUN_TIMEOUT, startHarness } from './harness.ts';
import type { Harness } from './harness.ts';

let harness: Harness;
const shops: Shop[] = [];

beforeAll(async () => {
  harness = await startHarness();
}, RUN_TIMEOUT);

afterAll(async () => {
  await Promise.all(shops.map((s) => s.close()));
  await harness?.close();
});

async function runShop(vulns: string[]) {
  const shop = await startShop(vulns);
  shops.push(shop);
  const url = vulns.includes('transport.cleartext') ? shop.httpUrl : shop.url;
  return harness.run(harness.copy('shop'), {
    env: { PW_SEC_MODE: 'scan', APP_URL: url, PARTNER_URL: shop.partnerUrl },
  });
}

describe('reference test app (10-REQ-02, 10-REQ-02a)', () => {
  test(
    'the secure mode passes all e2e and API tests and is scanned',
    async () => {
      const run = await runShop([]);
      expect(
        run.results.map((r) => r.status),
        run.output,
      ).toEqual(Array(12).fill('passed'));
      const responses = run.results.reduce(
        (n, r) => n + (r.attachment?.coverage.responses ?? 0),
        0,
      );
      expect(responses).toBeGreaterThan(20);
      // NF-11 for the rules implemented so far; WP-13 checks the whole catalog.
      const findings = run.results.flatMap((r) => r.attachment?.findings ?? []);
      expect(findings.filter((f) => f.severity !== 'info').map((f) => f.fingerprint)).toEqual([]);
    },
    RUN_TIMEOUT,
  );

  test(
    'every switch keeps the tests green',
    async () => {
      const run = await runShop([...APP_RULES]);
      expect(
        run.results.filter((r) => r.status !== 'passed').map((r) => r.title),
        run.output,
      ).toEqual([]);
    },
    RUN_TIMEOUT,
  );
});
