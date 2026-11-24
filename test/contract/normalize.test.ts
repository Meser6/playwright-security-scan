// Golden normalization cases copied from the perf package (D-08): the copy of the module must
// give the same endpoint keys (01-REQ-11, 07-REQ-01).
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, test } from 'vitest';
import { createKeyBuilder, resolveNormalization } from '../../src/core/normalize/index.ts';
import type { NormalizationInput } from '../../src/core/normalize/index.ts';

interface NormalizeCase {
  id: string;
  title: string;
  config?: NormalizationInput;
  context?: { baseOrigins: string[] };
  input: { method: string; url: string };
  expected: { key: string } | { skip: string };
}

const file = JSON.parse(
  readFileSync(join(import.meta.dirname, '../golden/normalize/cases.json'), 'utf8'),
) as { defaultContext: { baseOrigins: string[] }; cases: NormalizeCase[] };

describe('07-REQ-01 endpoint keys match the perf package golden cases', () => {
  test.each(file.cases.map((c) => [`${c.id} ${c.title}`, c] as const))('%s', (_name, c) => {
    const build = createKeyBuilder(
      resolveNormalization(c.config ?? {}),
      c.context ?? file.defaultContext,
    );
    const result = build({ ...c.input, resourceType: 'fetch' });
    if ('key' in c.expected) {
      expect(result).toMatchObject({ ok: true, key: c.expected.key, issues: [] });
    } else {
      expect(result.ok).toBe(false);
      expect(result.issues.map((i) => i.code)).toEqual([c.expected.skip]);
    }
  });

  test('API traffic gets the same key as browser traffic, without a source prefix', () => {
    const build = createKeyBuilder(resolveNormalization(), {
      baseOrigins: ['https://app.example.com'],
    });
    const url = 'https://app.example.com/api/items/42';
    const browser = build({ method: 'GET', url, resourceType: 'fetch' });
    const api = build({ method: 'GET', url, resourceType: 'api' });
    expect(browser).toMatchObject({ ok: true, key: 'GET /api/items/:id' });
    expect(api).toMatchObject({ ok: true, key: 'GET /api/items/:id' });
  });
});
