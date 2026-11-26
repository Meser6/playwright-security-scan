// The create package (11-REQ-02) and the built binary without a terminal (11-AC-04): in a project
// where the package resolves, `create-playwright-security-scan` skips the installation and starts
// the wizard; without a terminal or with PW_SEC_DRY_RUN=1 nothing in the project changes.
import { spawnSync } from 'node:child_process';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { afterAll, beforeAll, describe, expect, test } from 'vitest';
import { RUN_TIMEOUT, startHarness } from './harness.ts';
import type { Harness } from './harness.ts';

const ROOT = join(import.meta.dirname, '../..');
let harness: Harness;

beforeAll(async () => {
  harness = await startHarness();
}, RUN_TIMEOUT);

afterAll(async () => {
  await harness?.close();
});

/** Every file below `dir` except node_modules: relative path → text. */
function tree(dir: string): Map<string, string> {
  const files = new Map<string, string>();
  const walk = (sub: string): void => {
    for (const name of readdirSync(sub).sort()) {
      if (name === 'node_modules') continue;
      const path = join(sub, name);
      if (statSync(path).isDirectory()) walk(path);
      else files.set(relative(dir, path), readFileSync(path, 'utf8'));
    }
  };
  walk(dir);
  return files;
}

function run(file: string, cwd: string, env: Record<string, string> = {}, args: string[] = []) {
  const r = spawnSync(process.execPath, [file, ...args], {
    cwd,
    env: { ...process.env, NO_COLOR: '1', ...env },
    input: '',
    encoding: 'utf8',
  });
  return { status: r.status, output: `${r.stdout}${r.stderr}` };
}

describe('create package and binary (11, chapter 3)', () => {
  test('11-AC-04 without a terminal and with PW_SEC_DRY_RUN=1 nothing changes; the plan is shown', () => {
    const dir = harness.copy('init-ts-fixtures');
    const before = tree(dir);
    const envs: Record<string, string>[] = [{}, { PW_SEC_DRY_RUN: '1' }];
    for (const env of envs) {
      const r = run(join(ROOT, 'dist/cli.js'), dir, env);
      expect(r.status, r.output).toBe(0);
      expect(r.output).toContain('[7/9]');
      expect(r.output).toContain('pw-sec.config.ts (new file)');
      expect(r.output).toContain('Planned changes (not written):');
      expect(tree(dir)).toEqual(before);
    }
  });

  test('11-REQ-02 with the package resolvable the create script skips the installation and starts the wizard', () => {
    const dir = harness.copy('init-ts-fixtures');
    const r = run(join(ROOT, 'create/index.js'), dir, { PW_SEC_NO_TUTORIAL: '1' });
    expect(r.status, r.output).toBe(0);
    expect(r.output).not.toContain('installing');
    expect(r.output).toContain('To set it up by hand');
  });

  test('11-REQ-02 the create script takes no arguments and needs a package.json', () => {
    const dir = harness.copy('init-ts-fixtures');
    const args = run(join(ROOT, 'create/index.js'), dir, {}, ['--yes']);
    expect(args.status).toBe(3);
    expect(args.output).toContain('takes no arguments');
    const empty = run(join(ROOT, 'create/index.js'), join(dir, 'tests'));
    expect(empty.status).toBe(3);
    expect(empty.output).toContain('no package.json');
  });
});
