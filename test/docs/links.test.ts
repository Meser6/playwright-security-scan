// 13-AC-03: every relative link in README.md and docs/**/*.md points to an existing file, and a link
// with an anchor to an existing heading (GitHub slugs).
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { describe, expect, test } from 'vitest';

const ROOT = join(import.meta.dirname, '../..');

function markdown(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? markdown(path) : path.endsWith('.md') ? [path] : [];
  });
}

/** GitHub heading anchors: lowercase, punctuation dropped, spaces to "-". */
export function slug(heading: string): string {
  return heading
    .trim()
    .toLowerCase()
    .replace(/`/g, '')
    .replace(/[^\p{L}\p{N} _-]/gu, '')
    .replace(/ /g, '-');
}

function anchors(file: string): Set<string> {
  const text = readFileSync(file, 'utf8').replace(/```[\s\S]*?```/g, '');
  const seen = new Map<string, number>();
  const out = new Set<string>();
  for (const m of text.matchAll(/^#{1,6} (.+)$/gm)) {
    const base = slug(m[1] ?? '');
    const n = seen.get(base) ?? 0;
    seen.set(base, n + 1);
    out.add(n === 0 ? base : `${base}-${n}`);
  }
  return out;
}

const files = [join(ROOT, 'README.md'), ...markdown(join(ROOT, 'docs'))];
const links: [string, string][] = [];
for (const file of files) {
  const text = readFileSync(file, 'utf8').replace(/```[\s\S]*?```/g, '');
  for (const m of text.matchAll(/\]\(([^)\s]+)\)/g)) {
    const target = m[1] ?? '';
    if (/^[a-z]+:/i.test(target)) continue;
    links.push([relative(ROOT, file), target]);
  }
}

describe('13-AC-03 relative links in README.md and docs/ resolve', () => {
  test('there are links to check', () => {
    expect(links.length).toBeGreaterThan(50);
  });

  test.each(links)('%s → %s', (from, target) => {
    const [path = '', anchor] = target.split('#');
    const file = path === '' ? join(ROOT, from) : join(dirname(join(ROOT, from)), path);
    expect(existsSync(file), `missing file ${relative(ROOT, file)}`).toBe(true);
    if (anchor !== undefined && file.endsWith('.md')) {
      expect([...anchors(file)], `missing #${anchor}`).toContain(anchor);
    }
  });
});
