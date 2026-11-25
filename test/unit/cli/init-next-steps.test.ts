// The IMPORTANT box of the wizard (11-REQ-13, 11-AC-09): commands from the test command and the
// environment labels, cross-env on Windows, golden text per platform and width limits.
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, test } from 'vitest';
import { runCommands } from '../../../src/cli/init/commands.ts';
import { LANGUAGES, translator } from '../../../src/cli/init/messages.ts';
import { importantBox, importantBoxWidth } from '../../../src/cli/init/next-steps.ts';
import { textWidth } from '../../../src/core/report/term/text.ts';

const GOLDEN = join(import.meta.dirname, '../../golden/init');

function golden(name: string, text: string): void {
  const file = join(GOLDEN, name);
  if (process.env.UPDATE_GOLDEN === '1' || !existsSync(file)) writeFileSync(file, text);
  expect(text).toBe(readFileSync(file, 'utf8'));
}

function render(platform: string, lang: (typeof LANGUAGES)[number] = 'en'): string {
  return importantBox(
    {
      t: translator(lang),
      commands: runCommands('npm run e2e', platform, ['qa', 'staging']),
      files: ['security-baseline.qa.json', 'security-baseline.staging.json'],
      reportDir: 'reports/pw-sec',
      fixFirst: false,
      windows: platform === 'win32',
      ciUrl: 'https://example.invalid/docs/ci.md',
    },
    { columns: 80, color: false, ascii: false },
  );
}

describe('IMPORTANT box (11-REQ-13)', () => {
  test('11-AC-09 commands with the test command and every label; golden text on linux and win32', () => {
    const linux = render('linux');
    expect(linux).toContain('PW_SEC_MODE=baseline PW_SEC_ENV=qa npm run e2e');
    expect(linux).toContain('PW_SEC_MODE=scan PW_SEC_ENV=staging npm run e2e');
    golden('important.linux.txt', linux);
    const win = render('win32');
    expect(win).toContain('npx cross-env PW_SEC_MODE=baseline PW_SEC_ENV=qa npm run e2e');
    expect(win).toContain('docs/cli.md (Windows)');
    golden('important.win32.txt', win);
  });

  test('11-REQ-13 every language fits the box width', () => {
    for (const lang of LANGUAGES) {
      for (const line of render('linux', lang).trimEnd().split('\n'))
        expect(textWidth(line), `${lang}: ${line}`).toBeLessThanOrEqual(80);
    }
    expect(importantBoxWidth(undefined)).toBe(80);
    expect(importantBoxWidth(200)).toBe(80);
    expect(importantBoxWidth(20)).toBe(40);
  });

  test('11-REQ-13 without labels one baseline and one scan command', () => {
    const c = runCommands('npx playwright test', 'linux');
    expect(c).toEqual({
      base: 'npx playwright test',
      check: 'PW_SEC_MODE=check npx playwright test',
      baseline: ['PW_SEC_MODE=baseline npx playwright test'],
      scan: ['PW_SEC_MODE=scan npx playwright test'],
    });
  });
});
