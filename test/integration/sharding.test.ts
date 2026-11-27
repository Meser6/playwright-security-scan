// Sharded runs and the merge on real runs (17-AC-01, 17-AC-02, 17-AC-03, 17-AC-05, 17-AC-06):
// three shards of test/projects/shop in separate copies, the merge in a fourth.
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, test } from 'vitest';
import type { OutcomeFile, RunReport } from '../../src/core/types/index.ts';
import { startShop } from '../app/shop.ts';
import type { Shop } from '../app/shop.ts';
import { ROOT, RUN_TIMEOUT, startHarness } from './harness.ts';
import type { Harness } from './harness.ts';

let harness: Harness;
let shop: Shop;

// Findings of several rules and scopes, some of them blocking.
const VULNS = [
  'header.xcto-missing',
  'header.clickjacking',
  'cookie.no-httponly',
  'disclosure.server-version',
  'data.token-in-url',
  'browser.reflected-param',
];

beforeAll(async () => {
  harness = await startHarness();
  shop = await startShop(VULNS);
}, RUN_TIMEOUT);

afterAll(async () => {
  await shop?.close();
  await harness?.close();
});

const env = (mode: string) => ({
  PW_SEC_MODE: mode,
  APP_URL: shop.url,
  PARTNER_URL: shop.partnerUrl,
});

interface MergeRun {
  status: number | null;
  output: string;
  report: RunReport | null;
  outcome: OutcomeFile | null;
  baseline: string | null;
}

/** `PW_SEC_MODE=merge npx pw-sec` in `dir` with the given shard files. */
function merge(dir: string, shards: Record<string, string>): Promise<MergeRun> {
  const reports = join(dir, 'reports/pw-sec');
  rmSync(join(dir, 'reports'), { recursive: true, force: true });
  mkdirSync(reports, { recursive: true });
  for (const [name, text] of Object.entries(shards)) writeFileSync(join(reports, name), text);
  const clean = Object.fromEntries(
    Object.entries(process.env).filter(([name]) => !name.startsWith('PW_SEC_')),
  );
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [join(ROOT, 'dist/cli.js')], {
      cwd: dir,
      env: { ...clean, CI: '', NO_COLOR: '1', PW_SEC_MODE: 'merge' },
    });
    let output = '';
    child.stdout.on('data', (c: Buffer) => (output += c.toString()));
    child.stderr.on('data', (c: Buffer) => (output += c.toString()));
    child.on('error', reject);
    child.on('close', (status) => {
      const read = (path: string): string | null =>
        existsSync(path) ? readFileSync(path, 'utf8') : null;
      const report = read(join(reports, 'report.json'));
      const outcome = read(join(reports, 'outcome.json'));
      resolve({
        status,
        output,
        report: report === null ? null : (JSON.parse(report) as RunReport),
        outcome: outcome === null ? null : (JSON.parse(outcome) as OutcomeFile),
        baseline: read(join(dir, 'security-baseline.json')),
      });
    });
  });
}

/** Runs shard i/3 in its own copy and returns the shard file name and text. */
async function shardRuns(
  mode: string,
  options: { grepInShard2?: string } = {},
): Promise<Record<string, string>> {
  const files: Record<string, string> = {};
  for (const i of [1, 2, 3]) {
    const dir = harness.copy('shop');
    const args = [`--shard=${String(i)}/3`];
    if (i === 2 && options.grepInShard2 !== undefined) args.push('--grep', options.grepInShard2);
    const run = await harness.run(dir, { env: env(mode), args });
    const name = `shard-${String(i)}-of-3.json`;
    const file = join(dir, 'reports/pw-sec', name);
    expect(existsSync(file), run.output).toBe(true);
    files[name] = readFileSync(file, 'utf8');
  }
  return files;
}

/**
 * report.json without the fields that differ between any two runs (17-AC-02): times, run id,
 * shards, the order of the diagnostics and the evidence (each shard has its own redaction salt,
 * 07-REQ-15, so the same value has other hashes and the first 3 unique items may differ).
 */
function comparable(report: RunReport | null): unknown {
  if (report === null) return null;
  const { runId: _r, startedAt: _s, finishedAt: _f, shards: _sh, diagnostics, ...rest } = report;
  return {
    ...rest,
    findings: rest.findings.map(({ evidence: _e, ...f }) => f),
    diagnostics: [...diagnostics].sort((a, b) =>
      `${a.code} ${a.message}` < `${b.code} ${b.message}` ? -1 : 1,
    ),
  };
}

/** Removes the first entry of severity medium or above (the same edit in both runs). */
function dropFirstEntry(text: string): string {
  const doc = JSON.parse(text) as { findings: Record<string, { severity: string }> };
  const first = Object.keys(doc.findings)
    .sort()
    .find((p) => ['medium', 'high', 'critical'].includes(doc.findings[p]?.severity ?? ''));
  if (first === undefined) throw new Error('no blocking entry in the baseline');
  const findings = Object.fromEntries(Object.entries(doc.findings).filter(([p]) => p !== first));
  return `${JSON.stringify({ ...doc, findings }, null, 2)}\n`;
}

describe('sharded runs (17)', () => {
  test(
    '17-AC-01 17-AC-02 17-AC-03 17-AC-05 three shards and the merge give the result and the baseline of a run without shards',
    async () => {
      // A run without shards: baseline, one entry removed, scan.
      const single = harness.copy('shop');
      const baseline = await harness.run(single, { env: env('baseline') });
      expect(baseline.outcome?.code, baseline.output).toBe(0);
      const baselineText = baseline.baseline ?? '';
      expect(Object.keys(JSON.parse(baselineText).findings).length).toBeGreaterThan(3);
      writeFileSync(join(single, 'security-baseline.json'), dropFirstEntry(baselineText));
      const scan = await harness.run(single, { env: env('scan') });
      expect(scan.outcome?.code, scan.output).toBe(1);

      // 17-AC-01: a shard writes its shard file and outcome.json, nothing else.
      const one = harness.copy('shop');
      const shardRun = await harness.run(one, { env: env('scan'), args: ['--shard=1/3'] });
      expect(shardRun.outcome, shardRun.output).toMatchObject({
        code: 0,
        name: 'SHARD_WRITTEN',
        mode: 'scan',
        shard: { current: 1, total: 3 },
        newBlocking: null,
      });
      expect(shardRun.status).toBe(0);
      expect(shardRun.output).toContain('scan run · shard 1/3');
      expect(shardRun.output).toContain('Data: reports/pw-sec/shard-1-of-3.json');
      expect(shardRun.output).toContain('PW_SEC_MODE=merge npx pw-sec');
      expect(existsSync(join(one, 'reports/pw-sec/shard-1-of-3.json'))).toBe(true);
      for (const file of ['report.json', 'report.html', 'results.sarif', 'junit.xml']) {
        expect(existsSync(join(one, 'reports/pw-sec', file)), file).toBe(false);
      }
      expect(shardRun.baseline).toBeNull();

      // 17-AC-02: the same baseline and the same scan result through 3 shards and the merge.
      const merged = harness.copy('shop');
      const baselineShards = await shardRuns('baseline');
      const mergedBaseline = await merge(merged, baselineShards);
      expect(mergedBaseline.status, mergedBaseline.output).toBe(0);
      expect(mergedBaseline.output).toContain('merged from 3 shards');
      expect(mergedBaseline.baseline).toBe(baselineText);
      expect(mergedBaseline.report?.shards).toMatchObject({ total: 3, missing: [] });
      expect(mergedBaseline.report?.shards?.list.map((s) => s.index)).toEqual([1, 2, 3]);

      writeFileSync(join(merged, 'security-baseline.json'), dropFirstEntry(baselineText));
      const scanShards = await shardRuns('scan');
      const mergedScan = await merge(merged, scanShards);
      expect(mergedScan.status, mergedScan.output).toBe(1);
      expect(mergedScan.outcome).toEqual(scan.outcome);
      expect(comparable(mergedScan.report)).toEqual(comparable(scan.report));
      expect(existsSync(join(merged, 'reports/pw-sec/report.html'))).toBe(true);
      expect(readFileSync(join(merged, 'reports/pw-sec/report.html'), 'utf8')).toContain(
        'merged from <b>3</b> shards',
      );
      expect(existsSync(join(merged, 'reports/pw-sec/results.sarif'))).toBe(true);
      expect(existsSync(join(merged, 'reports/pw-sec/junit.xml'))).toBe(true);

      // 17-AC-03: a missing shard: code 3, the report of the other shards, no baseline written.
      const incomplete = harness.copy('shop');
      const missing = await merge(incomplete, {
        'shard-1-of-3.json': baselineShards['shard-1-of-3.json'] as string,
        'shard-3-of-3.json': baselineShards['shard-3-of-3.json'] as string,
      });
      expect(missing.status, missing.output).toBe(3);
      expect(missing.output).toContain('MERGE_SHARD_MISSING');
      expect(missing.output).toContain('shard 2/3 is missing');
      expect(missing.outcome?.name).toBe('TOOL_ERROR');
      expect(missing.report?.shards).toMatchObject({ total: 3, missing: [2] });
      expect(missing.baseline).toBeNull();

      // 17-AC-05: a baseline through 3 shards removes a resolved entry; with --grep in one shard
      // it keeps it and says PARTIAL_RUN.
      const doc = JSON.parse(baselineText) as { findings: Record<string, unknown> };
      const resolvedPrint = `header.csp-missing|origin|${new URL(shop.url).origin}`;
      expect(Object.keys(doc.findings)).not.toContain(resolvedPrint);
      doc.findings[resolvedPrint] = {
        ruleId: 'header.csp-missing',
        subject: new URL(shop.url).origin,
        severity: 'medium',
        status: 'accepted',
        addedAt: '2026-01-01',
      };
      const withResolved = `${JSON.stringify(doc, null, 2)}\n`;
      writeFileSync(join(merged, 'security-baseline.json'), withResolved);
      const pruned = await merge(merged, baselineShards);
      expect(pruned.status, pruned.output).toBe(0);
      expect(pruned.baseline).toBe(baselineText);

      writeFileSync(join(merged, 'security-baseline.json'), withResolved);
      const partial = await merge(merged, await shardRuns('baseline', { grepInShard2: 'API' }));
      expect(partial.output).toContain('PARTIAL_RUN');
      expect(Object.keys(JSON.parse(partial.baseline ?? '{}').findings)).toContain(resolvedPrint);
    },
    RUN_TIMEOUT * 2,
  );

  test(
    '17-AC-06 PW_SEC_MODE=merge in the test command stops before any test',
    async () => {
      const run = await harness.run(harness.copy('shop'), { env: env('merge') });
      expect(run.status).not.toBe(0);
      expect(run.results).toEqual([]);
      expect(run.output).toContain('MODE_INVALID');
      expect(run.output).toContain('PW_SEC_MODE=merge npx pw-sec');
    },
    RUN_TIMEOUT,
  );
});
