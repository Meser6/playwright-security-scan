// The init wizard, WP-26 part (11, chapters 3 and 4): variables, texts, the tutorial question,
// the language, a project without playwright.config and a too old Playwright.
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, test } from 'vitest';
import { MIN_PLAYWRIGHT_VERSION } from '../../../src/cli/constants.ts';
import { readInitEnv } from '../../../src/cli/env.ts';
import { main } from '../../../src/cli/main.ts';
import { LANGUAGES, MESSAGES, placeholders } from '../../../src/cli/init/messages.ts';
import type { Prompt } from '../../../src/cli/host.ts';
import { fakeCliHost } from './harness.ts';

const dirs: string[] = [];
afterAll(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

function project(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'pw-sec init-'));
  dirs.push(dir);
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(join(dir, path, '..'), { recursive: true });
    writeFileSync(join(dir, path), text);
  }
  return dir;
}

const CONFIG =
  "import { defineConfig } from '@playwright/test';\nexport default defineConfig({ testDir: './tests' });\n";

/** A terminal that answers the questions in order. */
function answers(...list: string[]): () => Prompt {
  return () => ({
    ask: () => Promise.resolve(list.shift() ?? ''),
    close: () => undefined,
  });
}

const out = (lines: string[]): string => lines.join('');

describe('init wizard: start (11, chapters 3 and 4)', () => {
  test('11-AC-07 every language has every key with the same placeholders', () => {
    expect(LANGUAGES).toEqual(['en', 'es', 'fr', 'pl', 'it', 'uk', 'ru']);
    const keys = Object.keys(MESSAGES.en).sort();
    for (const lang of LANGUAGES) {
      const texts: Record<string, string> = MESSAGES[lang];
      expect(Object.keys(texts).sort(), lang).toEqual(keys);
      for (const key of keys) {
        const en = MESSAGES.en[key as keyof typeof MESSAGES.en];
        expect((texts[key] ?? '').trim(), `${lang}.${key}`).not.toBe('');
        expect(placeholders(texts[key] ?? ''), `${lang}.${key}`).toEqual(placeholders(en));
        for (const literal of new Set(
          en.match(/\b[\w.]+\(\)|@playwright\/test|PW_SEC_\w+/gu) ?? [],
        ))
          expect(texts[key], `${lang}.${key} keeps ${literal}`).toContain(literal);
      }
    }
  });

  test('11-REQ-03 PW_SEC_LANG, PW_SEC_DRY_RUN and PW_SEC_NO_TUTORIAL are checked before any question', async () => {
    expect(readInitEnv({ PW_SEC_LANG: 'PL', PW_SEC_DRY_RUN: '1' }, LANGUAGES)).toEqual({
      ok: true,
      value: { dryRun: true, noTutorial: false, lang: 'pl' },
    });
    const envs: Record<string, string>[] = [
      { PW_SEC_LANG: 'xx' },
      { PW_SEC_DRY_RUN: 'yes' },
      { PW_SEC_NO_TUTORIAL: '0' },
    ];
    for (const env of envs) {
      const fake = fakeCliHost({ cwd: project({ 'playwright.config.ts': CONFIG }), env });
      expect(await main([], fake.host)).toBe(3);
      expect(out(fake.stderr)).toContain('INIT_INVALID_VALUE');
      expect(fake.stdout).toEqual([]);
    }
  });

  test('11-REQ-01 the binary takes no arguments', async () => {
    const fake = fakeCliHost({ cwd: project({}) });
    expect(await main(['scan'], fake.host)).toBe(3);
    expect(out(fake.stderr)).toContain('CLI_UNKNOWN_COMMAND');
    expect(out(fake.stderr)).toContain('PW_SEC_MODE=scan');
  });

  test('11-AC-05 "no" to the tutorial and PW_SEC_NO_TUTORIAL=1 end with 0 and change nothing', async () => {
    const dir = project({ 'playwright.config.ts': CONFIG });
    const declined = fakeCliHost({ cwd: dir, prompt: answers('n') });
    expect(await main([], declined.host)).toBe(0);
    expect(out(declined.stdout)).toContain('withSecurity()');
    expect(declined.written).toEqual([]);

    const variable = fakeCliHost({
      cwd: dir,
      prompt: answers(),
      env: { PW_SEC_NO_TUTORIAL: '1', PW_SEC_LANG: 'pl' },
    });
    expect(await main([], variable.host)).toBe(0);
    expect(out(variable.stdout)).toContain('Aby skonfigurować ręcznie');
    expect(variable.written).toEqual([]);
    expect(readFileSync(join(dir, 'playwright.config.ts'), 'utf8')).toBe(CONFIG);
  });

  test('11-AC-06 no playwright.config: code 3, the config of a subdirectory with its command, nothing written', async () => {
    const dir = project({ 'e2e/playwright.config.ts': CONFIG, 'package.json': '{}' });
    const fake = fakeCliHost({ cwd: dir, prompt: answers('y', 'en') });
    expect(await main([], fake.host)).toBe(3);
    const err = out(fake.stderr);
    expect(err).toContain('INIT_NO_PLAYWRIGHT_CONFIG');
    expect(err).toContain('cd e2e && npx pw-sec   (e2e/playwright.config.ts)');
    expect(fake.written).toEqual([]);
  });

  test('11-REQ-04 without a terminal: default answers, step 1, nothing written', async () => {
    const fake = fakeCliHost({ cwd: project({ 'playwright.config.ts': CONFIG }) });
    expect(await main([], fake.host)).toBe(0);
    expect(out(fake.stderr)).toContain('no terminal');
    expect(out(fake.stdout)).toContain('[1/8] The package and how to use it');
    expect(out(fake.stdout)).toContain('PW_SEC_MODE=check <your test command>');
    expect(fake.written).toEqual([]);
  });

  test('11-REQ-04 an old @playwright/test stops with INIT_PLAYWRIGHT_TOO_OLD', async () => {
    const fake = fakeCliHost({
      cwd: project({ 'playwright.config.ts': CONFIG }),
      playwright: { cliPath: '/x/cli.js', version: '1.50.0' },
    });
    expect(await main([], fake.host)).toBe(3);
    expect(out(fake.stderr)).toContain('INIT_PLAYWRIGHT_TOO_OLD');
  });

  test('the lowest Playwright version is the peer dependency of package.json', () => {
    const pkg = JSON.parse(
      readFileSync(join(import.meta.dirname, '../../../package.json'), 'utf8'),
    ) as {
      peerDependencies: Record<string, string>;
    };
    expect(pkg.peerDependencies['@playwright/test']).toBe(`>=${MIN_PLAYWRIGHT_VERSION}`);
  });
  test('11-AC-03 steps 2 to 7 write the answers; a second run changes nothing', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'pw-sec init-'));
    dirs.push(dir);
    cpSync(join(import.meta.dirname, '../../projects/init-ts-fixtures'), dir, { recursive: true });
    // tutorial, language, Enter after step 1, preset, gate, origins, command, then "yes" to every
    // change.
    const first = fakeCliHost({
      cwd: dir,
      prompt: answers(
        'y',
        'en',
        '',
        'strict',
        'high',
        'https://api.example.test',
        'skip',
        'y',
        'y',
        'y',
        'y',
      ),
    });
    expect(await main([], first.host)).toBe(0);
    const text = out(first.stdout);
    expect(text).toContain('[6/8] Changes');
    expect(text).toContain('Setup finished.');
    const config = readFileSync(join(dir, 'pw-sec.config.ts'), 'utf8');
    expect(config).toContain("preset: 'strict',");
    expect(config).toContain("minSeverity: 'high',");
    expect(config).toContain("origins: ['https://api.example.test'],");
    expect(readFileSync(join(dir, 'playwright.config.ts'), 'utf8')).toContain(
      'withSecurity(defineConfig(',
    );
    expect(readFileSync(join(dir, 'tests/fixtures.ts'), 'utf8')).toContain(
      'withSecurityFixtures(base.extend',
    );
    expect(readFileSync(join(dir, '.gitignore'), 'utf8')).toContain('reports/pw-sec/');

    const second = fakeCliHost({
      cwd: dir,
      prompt: answers('y', 'en', '', '', '', '', 'skip'),
    });
    expect(await main([], second.host)).toBe(0);
    expect(out(second.stdout)).toContain('Nothing to change: the project is already set up.');
    expect(second.written).toEqual([]);
  });

  test('11-REQ-08 an invalid origin is asked again', async () => {
    const dir = project({ 'playwright.config.ts': CONFIG });
    const fake = fakeCliHost({
      cwd: dir,
      prompt: answers(
        'y',
        'en',
        '',
        '',
        '',
        'api.example.test',
        'https://api.example.test',
        'skip',
        'n',
        'n',
        'n',
      ),
    });
    expect(await main([], fake.host)).toBe(0);
    const text = out(fake.stdout);
    expect(text).toContain('"api.example.test" is not an origin');
    expect(fake.written).toEqual([]);
  });

  describe('11-AC-10 eight steps [1/8] to [8/8] and no question about environments', () => {
    test.each(LANGUAGES.map((lang) => [lang]))('%s', async (lang) => {
      const dir = project({ 'playwright.config.ts': CONFIG });
      const asked: string[] = [];
      const list = ['y', lang, '', '', '', '', 'skip', 'n', 'n', 'n'];
      const fake = fakeCliHost({
        cwd: dir,
        prompt: () => ({
          ask: (question: string) => {
            asked.push(question);
            return Promise.resolve(list.shift() ?? '');
          },
          close: () => undefined,
        }),
      });
      expect(await main([], fake.host)).toBe(0);
      const text = out(fake.stdout);
      const steps = [...text.matchAll(/\[(\d)\/(\d)\]/gu)].map((m) => `${m[1]}/${m[2]}`);
      expect(steps).toEqual(['0/8', '1/8', '2/8', '3/8', '4/8', '5/8', '6/8', '7/8', '8/8']);
      expect(`${text}\n${asked.join('\n')}`).not.toMatch(/PW_SEC_ENV|qa, staging/u);
    });
  });
});
