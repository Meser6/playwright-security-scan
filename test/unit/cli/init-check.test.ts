// The check of the init wizard (11, chapter 7): one run of the test command with PW_SEC_MODE=check,
// its result read from the output of the check (04-REQ-12).
import { cpSync, existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, test } from 'vitest';
import { main } from '../../../src/cli/main.ts';
import { readCheckOutput } from '../../../src/cli/init/check-output.ts';
import type { Prompt } from '../../../src/cli/host.ts';
import { formatCheck } from '../../../src/core/report/check.ts';
import type { CheckInput } from '../../../src/core/report/check.ts';
import { fakeCliHost } from './harness.ts';

const dirs: string[] = [];
afterAll(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

function answers(...list: string[]): () => Prompt {
  return () => ({ ask: () => Promise.resolve(list.shift() ?? ''), close: () => undefined });
}

const READY: CheckInput = {
  env: null,
  tests: { ran: 2, selected: 5, passed: 2, failed: 0, skipped: 3 },
  maxTests: 10,
  origins: [{ origin: 'http://localhost:3000', source: 'baseURL', responses: 12, documents: 2 }],
  outOfScope: {},
  responses: 12,
  apiResponses: 4,
  testsWithApi: 1,
  projects: ['chromium'],
  enabledRules: 30,
  preset: 'recommended',
  baseline: 'security-baseline.json (not found)',
  findings: 3,
  newAboveGate: 1,
  minSeverity: 'medium',
  diagnostics: [],
};

const NO_TRAFFIC: CheckInput = {
  ...READY,
  origins: [{ origin: 'http://localhost:3000', source: 'baseURL', responses: 0, documents: 0 }],
  outOfScope: { 'https://api.example.test': 7, 'https://cdn.example.test': 2 },
  responses: 0,
  apiResponses: 0,
  testsWithApi: 0,
};

const TOOL_ERROR: CheckInput = {
  ...READY,
  diagnostics: [
    { level: 'error', code: 'CONFIG_INVALID', message: 'gate.minSeverity: unknown value' },
    { level: 'warn', code: 'PARTIAL_RUN', message: 'a filter is active' },
  ],
};

function printed(input: CheckInput, color: boolean, ascii = false): string {
  return [
    'Running 5 tests using 1 worker',
    '  ✓  1 [chromium] › tests/a.spec.ts:3:1 › READY state of the cart (1.2s)',
    ...formatCheck(input, { width: 80, color, ascii }),
    '',
  ].join('\n');
}

describe('init wizard: the check output (11-REQ-11)', () => {
  test.each([
    [false, false],
    [true, false],
    [false, true],
  ])('11-REQ-11 reads the verdict of the check output (color %s, ascii %s)', (color, ascii) => {
    expect(readCheckOutput(printed(READY, color, ascii))).toEqual({
      verdict: 'ready',
      noTraffic: false,
      firstError: null,
      outOfScope: [],
    });
    expect(readCheckOutput(printed(NO_TRAFFIC, color, ascii))).toEqual({
      verdict: 'not-ready',
      noTraffic: true,
      firstError: null,
      outOfScope: ['https://api.example.test', 'https://cdn.example.test'],
    });
    expect(readCheckOutput(printed(TOOL_ERROR, color, ascii))).toEqual({
      verdict: 'not-ready',
      noTraffic: false,
      firstError: { code: 'CONFIG_INVALID', message: 'gate.minSeverity: unknown value' },
      outOfScope: [],
    });
  });

  test('11-REQ-11 no check output (the reporter is not loaded) is no result', () => {
    expect(readCheckOutput('Running 5 tests using 1 worker\n  5 passed (3.1s)\n')).toBeNull();
  });
});

/** The wizard on a copy of the TS project with every change applied and "yes" to the check. */
async function wizardWithCheck(
  input: CheckInput | null,
  code = 0,
): Promise<{ text: string; fake: ReturnType<typeof fakeCliHost>; dir: string }> {
  const dir = mkdtempSync(join(tmpdir(), 'pw-sec init-'));
  dirs.push(dir);
  cpSync(join(import.meta.dirname, '../../projects/init-ts-fixtures'), dir, { recursive: true });
  const fake = fakeCliHost({
    cwd: dir,
    // tutorial, language, Enter, preset, gate, origins, environments, command, four changes,
    // the check.
    prompt: answers('y', 'en', '', '', '', '', 'n', '', 'y', 'y', 'y', 'y', 'y'),
    onSpawn: (f) => {
      if (input !== null) f.child.print(printed(input, false));
      f.child.exit(code);
    },
  });
  expect(await main([], fake.host)).toBe(0);
  return { text: fake.stdout.join(''), fake, dir };
}

describe('init wizard: the check (11, chapter 7)', () => {
  test('11-AC-02 the check is one run with PW_SEC_MODE=check; READY prints the success line', async () => {
    const { text, fake, dir } = await wizardWithCheck(READY);
    expect(fake.spawned).toHaveLength(1);
    const env = fake.spawned[0]?.options.env ?? {};
    expect(env.PW_SEC_MODE).toBe('check');
    expect(Object.keys(env).filter((k) => k.startsWith('PW_SEC_'))).toEqual(['PW_SEC_MODE']);
    expect(text).toContain('$ PW_SEC_MODE=check npx playwright test');
    expect(text).toContain('READY');
    expect(text).toContain('check run: exit code 0');
    expect(text).toContain("✔ The scan sees your app's traffic.");
    expect(text).not.toContain('baseline run');
    expect(text).not.toContain('scan run');
    expect(text).toContain('IMPORTANT');
    expect(existsSync(join(dir, 'security-baseline.json'))).toBe(false);
  });

  test('11-REQ-11 NO_TRAFFIC: the fix with the config file and the origins outside the scope', async () => {
    const { text } = await wizardWithCheck(NO_TRAFFIC);
    expect(text).not.toContain("The scan sees your app's traffic.");
    expect(text).toContain(
      "Most likely cause: no response was in scope: set use.baseURL or add your app's origin to scope.origins in pw-sec.config.ts. Traffic outside the scope: https://api.example.test, https://cdn.example.test.",
    );
  });

  test('11-REQ-11 an error: its code and message; the exit code of the check does not change the code of the wizard', async () => {
    const { text } = await wizardWithCheck(TOOL_ERROR, 1);
    expect(text).toContain('check run: exit code 1');
    expect(text).toContain('Most likely cause: CONFIG_INVALID: gate.minSeverity: unknown value');
    expect(text).not.toContain("The scan sees your app's traffic.");
  });

  test('11-REQ-10 Ctrl+C stops the check with code 130', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'pw-sec init-'));
    dirs.push(dir);
    cpSync(join(import.meta.dirname, '../../projects/init-ts-fixtures'), dir, { recursive: true });
    const fake = fakeCliHost({
      cwd: dir,
      prompt: answers('y', 'en', '', '', '', '', 'n', '', 'y', 'y', 'y', 'y', 'y'),
      onSpawn: (f) => f.child.exit(null, 'SIGINT'),
    });
    expect(await main([], fake.host)).toBe(130);
    expect(fake.spawned).toHaveLength(1);
  });
});
