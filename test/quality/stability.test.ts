// Stable fingerprints (07-AC-01, 07-AC-02) and no trace of the package outside scan mode (S-06).
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, test } from 'vitest';
import { startShop } from '../app/shop.ts';
import type { Shop } from '../app/shop.ts';
import { RUN_TIMEOUT, startHarness } from '../integration/harness.ts';
import type { Harness, ProjectRun } from '../integration/harness.ts';

const VULNS = [
  'data.secret-in-asset',
  'disclosure.source-map',
  'header.csp-unsafe',
  'cookie.no-httponly',
  'data.token-in-url',
];
let harness: Harness;
const shops: Shop[] = [];

beforeAll(async () => {
  harness = await startHarness();
}, RUN_TIMEOUT);
afterAll(async () => {
  await Promise.all(shops.map((s) => s.close()));
  await harness?.close();
});

async function scan(
  shop: Shop,
  env: Record<string, string> = { PW_SEC_MODE: 'scan' },
): Promise<ProjectRun> {
  return harness.run(harness.copy('shop'), {
    env: { ...env, APP_URL: shop.url, PARTNER_URL: shop.partnerUrl },
  });
}

/** Fingerprints with the origins of the instance replaced, so instances on other ports compare. */
const prints = (run: ProjectRun, shop: Shop): string[] =>
  (run.report?.findings ?? [])
    .map((f) =>
      f.fingerprint.replaceAll(shop.url, 'https://APP').replaceAll(new URL(shop.url).host, 'APP'),
    )
    .sort();

describe('stability (07, chapter 6)', () => {
  test(
    '07-AC-01 two runs on the unchanged app give the same fingerprints',
    async () => {
      const shop = await startShop(VULNS);
      shops.push(shop);
      const a = await scan(shop);
      const b = await scan(shop);
      expect(prints(a, shop).length).toBeGreaterThanOrEqual(VULNS.length);
      expect(prints(b, shop)).toEqual(prints(a, shop));
    },
    RUN_TIMEOUT * 2,
  );

  test(
    '07-AC-02 a rebuilt frontend (new chunk hashes) keeps the fingerprints',
    async () => {
      const before = await startShop(VULNS, { build: 'release-1' });
      const after = await startShop(VULNS, { build: 'release-2' });
      shops.push(before, after);
      const a = await scan(before);
      const b = await scan(after);
      const assets = prints(a, before).filter((p) => p.includes('/static/app.*.js'));
      expect(assets.length).toBe(2);
      expect(prints(b, after)).toEqual(prints(a, before));
    },
    RUN_TIMEOUT * 2,
  );

  test(
    'S-06 without PW_SEC_MODE a run leaves no trace of the package',
    async () => {
      const shop = await startShop(VULNS);
      shops.push(shop);
      const run = await scan(shop, {});
      expect(run.status, run.output).toBe(0);
      expect(run.results.every((r) => r.status === 'passed' && r.attachment === null)).toBe(true);
      expect(existsSync(join(run.dir, 'reports'))).toBe(false);
      expect(run.output).not.toContain('pw-sec');
      expect(run.baseline).toBeNull();
    },
    RUN_TIMEOUT,
  );
});
