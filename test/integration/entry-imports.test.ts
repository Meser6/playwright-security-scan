// 01-AC-01: the config entry point does not load the collector or the rule code. Runs on dist/
// (`pnpm build` first), following the static imports of the built entry.
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { describe, expect, test } from 'vitest';

const DIST = join(import.meta.dirname, '../../dist');

function graph(entry: string): string[] {
  const seen = new Set<string>();
  const queue = [join(DIST, entry)];
  while (queue.length > 0) {
    const file = queue.pop() as string;
    if (seen.has(file)) continue;
    seen.add(file);
    const source = readFileSync(file, 'utf8');
    for (const m of source.matchAll(
      /(?:from\s*|import\s*\(\s*|require\(\s*)["'](\.\/[^"']+)["']/g,
    )) {
      queue.push(join(dirname(file), m[1] as string));
    }
  }
  return [...seen];
}

// Strings only the collector and the rule code contain.
const MARKERS = [
  'securitypolicyviolation',
  'addInitScript',
  'requestfinished',
  'Traceback (most recent call last)',
];

const built = existsSync(join(DIST, 'config.js'));

describe('01-AC-01 the config entry point does not load collector/ or core/rules/', () => {
  test.skipIf(!built).each(['config.js', 'config.cjs'])(
    '%s and its chunks have no collector or rule code',
    (entry) => {
      const files = graph(entry);
      for (const file of files) {
        const source = readFileSync(file, 'utf8');
        for (const marker of MARKERS)
          expect(source.includes(marker), `${marker} in ${file}`).toBe(false);
      }
    },
  );
});

describe('01-AC-03 the package never routes requests (P-04)', () => {
  test.skipIf(!built)('no route() call in dist/', () => {
    const files = readdirSync(DIST).filter((f) => /\.(c?js)$/.test(f));
    expect(files.length).toBeGreaterThan(0);
    for (const file of files) {
      const source = readFileSync(join(DIST, file), 'utf8');
      expect(/\.(route|routeFromHAR|routeWebSocket)\s*\(/.test(source), file).toBe(false);
    }
  });
});

/** Static imports only: `import(` is not followed. */
function staticGraph(entry: string): string[] {
  const seen = new Set<string>();
  const queue = [join(DIST, entry)];
  while (queue.length > 0) {
    const file = queue.pop() as string;
    if (seen.has(file)) continue;
    seen.add(file);
    const source = readFileSync(file, 'utf8');
    for (const m of source.matchAll(/(?:from\s*|require\(\s*)["'](\.\/[^"']+)["']/g)) {
      queue.push(join(dirname(file), m[1] as string));
    }
  }
  return [...seen];
}

describe('01-AC-03 18-AC-06 the code that sends requests is loaded only with import()', () => {
  test.skipIf(!built)(
    'active/ is a chunk of its own, imported dynamically by the reporter only',
    () => {
      const files = readdirSync(DIST).filter((f) => /\.(c?js)$/.test(f));
      const active = files.filter((f) =>
        readFileSync(join(DIST, f), 'utf8').includes('"x-pw-sec-probe"'),
      );
      expect(active.sort()).toEqual(files.filter((f) => f.startsWith('active-')).sort());
      expect(active).toHaveLength(2);
      for (const entry of ['config', 'fixture', 'reporter', 'rules', 'test']) {
        for (const ext of ['js', 'cjs']) {
          const reached = staticGraph(`${entry}.${ext}`).map((f) => f.split(/[\\/]/).pop());
          for (const chunk of active) expect(reached, `${entry}.${ext}`).not.toContain(chunk);
        }
      }
      for (const chunk of active) {
        const users = files.filter((f) => readFileSync(join(DIST, f), 'utf8').includes(chunk));
        expect(users.sort(), chunk).toEqual([
          chunk.endsWith('.cjs') ? 'reporter.cjs' : 'reporter.js',
        ]);
        expect(readFileSync(join(DIST, users[0] as string), 'utf8')).toContain(
          `await import('./${chunk}')`,
        );
      }
    },
  );
});

describe('the rules entry point loads as ESM and CJS (16, chapter 12)', () => {
  test.skipIf(!built)('defineRule() from CJS makes a rule the ESM config accepts', async () => {
    const { createRequire } = await import('node:module');
    const require = createRequire(import.meta.url);
    const cjs = require(join(DIST, 'rules.cjs')) as typeof import('../../src/entries/rules.ts');
    const esm = (await import(
      join(DIST, 'rules.js')
    )) as typeof import('../../src/entries/rules.ts');
    const config = (await import(
      join(DIST, 'config.js')
    )) as typeof import('../../src/entries/config.ts');
    expect(typeof esm.defineRule).toBe('function');
    expect(esm.builtinRuleIds).toEqual(cjs.builtinRuleIds);
    const rule = cjs.defineRule({
      id: 'custom.cjs',
      defaultSeverity: 'low',
      defaultConfidence: 'high',
      scope: 'origin',
      docs: { title: 't', why: 'w', fix: 'f' },
      check: () => [],
    });
    expect(config.defineSecurityConfig({ rules: { custom: [rule] } }).rules?.custom).toEqual([
      rule,
    ]);
    const { validateConfig } = await import('../../src/core/config/index.ts');
    expect(validateConfig({ rules: { custom: [rule] } })).toEqual([]);
  });
});
