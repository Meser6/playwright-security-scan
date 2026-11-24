// NF-02: worker memory stays bounded over 200 tests with a 5 MB bundle: bodies are dropped after
// analysis and the bundle is read once per worker. Compared with the same run without the scan.
import { afterAll, beforeAll, describe, expect, test } from 'vitest';
import { RUN_TIMEOUT, startHarness } from '../integration/harness.ts';
import type { Harness, ProjectRun } from '../integration/harness.ts';

let harness: Harness;
beforeAll(async () => {
  harness = await startHarness();
}, RUN_TIMEOUT);
afterAll(async () => {
  await harness?.close();
});

const heap = (run: ProjectRun): number => {
  const values = [...run.output.matchAll(/PW_SEC_HEAP_MB=(\d+)/g)].map((m) => Number(m[1]));
  if (values.length === 0) throw new Error(`no heap line in:\n${run.output.slice(-2000)}`);
  return Math.max(...values);
};

describe('memory (NF-02)', () => {
  test(
    'the worker heap after 200 scanned tests stays within 150 MB of an unscanned run',
    async () => {
      const plain = await harness.run(harness.copy('memory'));
      const scanned = await harness.run(harness.copy('memory'), { env: { PW_SEC_MODE: 'scan' } });
      expect(scanned.results.filter((r) => r.status === 'passed')).toHaveLength(200);
      expect(
        heap(scanned) - heap(plain),
        `plain ${heap(plain)} MB, scanned ${heap(scanned)} MB`,
      ).toBeLessThan(150);
    },
    RUN_TIMEOUT * 2,
  );
});
