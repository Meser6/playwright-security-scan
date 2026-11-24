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
