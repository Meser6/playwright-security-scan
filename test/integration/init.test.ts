// 11-AC-02: the wizard on a copy of a real project with the reference app: every change applied,
// then the check runs check, baseline and scan for real; the project's baseline is not created.
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
    '11-AC-02 after the changes the check passes: check, baseline and scan end with 0; no project baseline',
    async () => {
      const dir = harness.copy('init-shop');
      const out: string[] = [];
      const real = nodeHost();
      const host = {
        ...real,
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
      expect(text).toContain('check run: exit code 0');
      expect(text).toContain('baseline run: exit code 0');
      expect(text).toContain('scan run: exit code 0');
      expect(text).toContain('The check passed');
      expect(text).toContain('IMPORTANT');
      expect(text).toContain('PW_SEC_MODE=baseline npx playwright test');
      expect(existsSync(join(dir, 'security-baseline.json'))).toBe(false);
      expect(readFileSync(join(dir, 'playwright.config.ts'), 'utf8')).toContain('withSecurity(');
      expect(readFileSync(join(dir, 'tests/fixtures.ts'), 'utf8')).toContain(
        'withSecurityFixtures(',
      );
    },
    RUN_TIMEOUT * 4,
  );
});
