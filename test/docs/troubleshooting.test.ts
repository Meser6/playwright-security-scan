// 13-REQ-09: docs/troubleshooting.md has a section for every code the package can report.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, test } from 'vitest';

const ROOT = join(import.meta.dirname, '../..');

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? sources(path) : path.endsWith('.ts') ? [path] : [];
  });
}

const NODE_CODES = new Set(['MODULE_NOT_FOUND']);
const codes = new Set<string>();
// Names of CI variables (commit, branch, build URL of the shard file), not codes of the package.
const NOT_CODES = new Set(['ci-info.ts']);
for (const file of sources(join(ROOT, 'src')).filter(
  (f) => !NOT_CODES.has(f.split(/[\\/]/).pop() ?? ''),
)) {
  for (const m of readFileSync(file, 'utf8').matchAll(/'([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)'/g)) {
    // Environment variable names are documented in docs/cli.md.
    // Node's own error codes are not codes of the package.
    if (!(m[1] ?? '').startsWith('PW_') && !NODE_CODES.has(m[1] ?? '')) codes.add(m[1] ?? '');
  }
}

describe('docs/troubleshooting.md (13-REQ-09)', () => {
  const doc = readFileSync(join(ROOT, 'docs/troubleshooting.md'), 'utf8');
  const headings = new Set([...doc.matchAll(/^### ([A-Z0-9_]+)$/gm)].map((m) => m[1]));

  test('the package reports at least the known codes', () => {
    expect(codes.size).toBeGreaterThan(30);
  });

  test.each([...codes].sort().map((c) => [c]))('%s has a section', (code) => {
    expect(headings.has(code)).toBe(true);
  });

  test('every result name has a section', () => {
    for (const name of ['OK', 'NEW_FINDINGS', 'BASELINE_EXPIRED', 'TOOL_ERROR', 'NO_TRAFFIC']) {
      expect(headings.has(name)).toBe(true);
    }
  });
});
