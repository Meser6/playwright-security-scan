// The change plan of the init wizard (11, chapter 6): golden diffs per project layout (11-AC-01),
// manual steps and the red box, the reverse order with perf, and no change on a set-up project.
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, test } from 'vitest';
import { detectProject, readProjectFiles } from '../../../src/cli/init/index.ts';
import { unifiedDiff } from '../../../src/cli/init/diff.ts';
import { planInitChanges } from '../../../src/cli/init/plan.ts';
import type { InitPlan } from '../../../src/cli/init/plan.ts';
import { configOptionPaths } from '../../../src/cli/init/sec-config.ts';
import type { InitAnswers } from '../../../src/cli/init/sec-config.ts';
import { fakeCliHost } from './harness.ts';

const PROJECTS = join(import.meta.dirname, '../../projects');
const GOLDEN = join(import.meta.dirname, '../../golden/init');

const DEFAULTS: InitAnswers = {
  preset: 'recommended',
  minSeverity: 'medium',
  origins: [],
  envs: [],
  command: 'npx playwright test',
  runCheck: false,
};

async function plan(name: string, answers: InitAnswers = DEFAULTS): Promise<InitPlan> {
  const dir = join(PROJECTS, name);
  const fake = fakeCliHost({ cwd: dir, playwright: null });
  return planInitChanges(detectProject(await readProjectFiles(fake.host, dir)), answers);
}

function diffText(p: InitPlan): string {
  return [...p.changes]
    .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))
    .map(unifiedDiff)
    .join('');
}

/** Compares with test/golden/init/<name>.diff; UPDATE_GOLDEN=1 writes it. */
function golden(name: string, text: string): void {
  const file = join(GOLDEN, `${name}.diff`);
  if (process.env.UPDATE_GOLDEN === '1' || !existsSync(file)) writeFileSync(file, text);
  expect(text).toBe(readFileSync(file, 'utf8'));
}

describe('init plan (11, chapter 6)', () => {
  test.each([
    ['init-ts-fixtures'],
    ['init-esm-js'],
    ['init-cjs-js'],
    ['init-imports'],
    ['init-perf'],
    ['init-perf-reverse'],
    ['init-unknown'],
  ])('11-AC-01 %s: the diffs equal the golden file', async (name) => {
    golden(name, diffText(await plan(name)));
  });

  test('11-AC-01 answers go into pw-sec.config.ts with their defaults in the comment', async () => {
    const p = await plan('init-ts-fixtures', {
      ...DEFAULTS,
      preset: 'strict',
      minSeverity: 'high',
      origins: ['https://api.example.test'],
    });
    golden('init-ts-fixtures-answers', diffText(p));
    const config = p.changes.find((c) => c.path === 'pw-sec.config.ts')?.after ?? '';
    expect(config).toContain("preset: 'strict',");
    expect(config.replace(/\n\s*\/\/ /gu, ' ')).toContain("Default: 'recommended'.");
    expect(config).toContain("origins: ['https://api.example.test'],");
    expect(configOptionPaths(DEFAULTS).length).toBeLessThanOrEqual(12);
  });

  test('11-REQ-08 withSecurity() goes outside withPerf(), also when the order was reversed', async () => {
    const perf = await plan('init-perf');
    const config = perf.changes.find((c) => c.path === 'playwright.config.ts')?.after ?? '';
    expect(config).toContain('export default withSecurity(withPerf(defineConfig');
    const reverse = await plan('init-perf-reverse');
    const fixed = reverse.changes.find((c) => c.path === 'playwright.config.ts')?.after ?? '';
    expect(fixed).toContain(
      "export default withSecurity(withPerf(defineConfig({ testDir: './tests' }), perfConfig));",
    );
  });

  test('11-REQ-08 test files importing @playwright/test get the /test import, setup files do not', async () => {
    const p = await plan('init-imports');
    expect(p.importSwap?.paths.sort()).toEqual(['tests/a.spec.ts', 'tests/b.spec.ts']);
    const a = p.changes.find((c) => c.path === 'tests/a.spec.ts')?.after ?? '';
    expect(a).toContain("import { type Page } from '@playwright/test';");
    expect(a).toContain("import { test, expect } from 'playwright-security-scan/test';");
    expect(p.changes.some((c) => c.path === 'tests/auth.setup.ts')).toBe(false);
  });

  test('11-REQ-08 an unknown layout: manual steps and the red box, no change to the config', async () => {
    const p = await plan('init-unknown');
    expect(p.changes.some((c) => c.path === 'playwright.config.ts')).toBe(false);
    expect(p.manualSteps.map((m) => m.code)).toContain('INIT_MANUAL_STEP');
    expect(p.testObject).not.toBeNull();
  });

  test('11-AC-03 a project that is set up gets no change', async () => {
    expect(
      (await plan('shop')).changes.filter(
        (c) => c.path !== 'pw-sec.config.ts' && c.path !== '.gitignore',
      ),
    ).toEqual([]);
  });

  test('11, step 4: the baseURL origin and other origins of the sources, without third parties', async () => {
    const dir = join(PROJECTS, 'init-ts-fixtures');
    const fake = fakeCliHost({ cwd: dir, playwright: null });
    const info = detectProject(await readProjectFiles(fake.host, dir));
    expect(info.baseOrigin).toBe('https://shop.example.test');
    expect(info.foundOrigins).toEqual(['https://api.example.test']);
  });
});
