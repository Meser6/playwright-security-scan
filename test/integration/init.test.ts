// 11-AC-02: the wizard on a copy of a real project with the reference app: every change applied,
// then the check runs once for real with PW_SEC_MODE=check; no baseline and no report are written.
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, test } from 'vitest';
import { main } from '../../src/cli/main.ts';
import { nodeHost } from '../../src/cli/node-host.ts';
import type { Prompt } from '../../src/cli/host.ts';
import { startShop } from '../app/shop.ts';
import type { Shop } from '../app/shop.ts';
import { RUN_TIMEOUT, startHarness } from './harness.ts';
import type { Harness } from './harness.ts';

let harness: Harness;
let shop: Shop;

beforeAll(async () => {
  harness = await startHarness();
  shop = await startShop([]);
}, RUN_TIMEOUT);

afterAll(async () => {
  await shop?.close();
  await harness?.close();
});

/** A terminal that answers the questions in order. */
function answers(...list: string[]): () => Prompt {
  return () => ({ ask: () => Promise.resolve(list.shift() ?? ''), close: () => undefined });
}

describe('init wizard on a real project (11, chapter 7)', () => {
  test(
    '11-AC-02 after the changes one check run is READY; no baseline, no report, no baseline or scan run',
    async () => {
      const dir = harness.copy('init-shop');
      const out: string[] = [];
      const real = nodeHost();
      let runs = 0;
      const host = {
        ...real,
        spawnProcess: (...args: Parameters<typeof real.spawnProcess>) => {
          runs += 1;
          return real.spawnProcess(...args);
        },
        cwd: dir,
        env: {
          ...process.env,
          APP_URL: shop.url,
          PARTNER_URL: shop.partnerUrl,
          NO_COLOR: '1',
          CI: '',
        },
        stdin: { isTTY: true },
        stdout: { write: (text: string) => out.push(text), isTTY: true, columns: 100 },
        stderr: { write: (text: string) => out.push(text) },
        // tutorial, language, Enter, preset, gate, origins, environments, command, four changes,
        // the check.
        createPrompt: answers('y', 'en', '', '', '', '', 'n', '', 'y', 'y', 'y', 'y', 'y'),
      };
      const code = await main([], host);
      const text = out.join('');
      expect(code, text).toBe(0);
      expect(runs).toBe(1);
      // On Windows the command is shown with npx cross-env in front.
      expect(text).toMatch(/\$ (?:npx cross-env )?PW_SEC_MODE=check npx playwright test/u);
      expect(text).toMatch(/READY\b/u);
      expect(text).toContain('check run: exit code 0');
      expect(text).toContain("The scan sees your app's traffic.");
      expect(text).not.toContain('baseline run');
      expect(text).not.toContain('scan run');
      expect(text).toContain('IMPORTANT');
      expect(text).toContain('PW_SEC_MODE=baseline npx playwright test');
      expect(existsSync(join(dir, 'security-baseline.json'))).toBe(false);
      expect(existsSync(join(dir, 'reports/pw-sec/report.json'))).toBe(false);
      expect(readFileSync(join(dir, 'playwright.config.ts'), 'utf8')).toContain('withSecurity(');
      expect(readFileSync(join(dir, 'tests/fixtures.ts'), 'utf8')).toContain(
        'withSecurityFixtures(',
      );
    },
    RUN_TIMEOUT * 2,
  );
});
