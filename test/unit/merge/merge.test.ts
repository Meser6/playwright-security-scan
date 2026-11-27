// The shard merge (17): shard file format, validation of the set, combination and the binary.
import { mkdirSync, mkdtempSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, test } from 'vitest';
import { resolveConfig } from '../../../src/core/config/index.ts';
import type { ResolvedSecurityConfig } from '../../../src/core/config/index.ts';
import { emptyCoverage } from '../../../src/core/coverage.ts';
import { dedupeRun } from '../../../src/core/fingerprint/index.ts';
import type { Finding, TestContextRef } from '../../../src/core/types/index.ts';
import { defineRule } from '../../../src/entries/rules.ts';
import {
  combineShards,
  configFromSnapshot,
  runMerge,
  validateShardSet,
} from '../../../src/merge/index.ts';
import { isMergeMode, readMode } from '../../../src/mode/index.ts';
import { isPartialRun } from '../../../src/reporter/partial.ts';
import {
  configSnapshot,
  isShardFileName,
  parseShardFile,
  SHARD_FILE_FORMAT,
  SHARD_FILE_VERSION,
  shardFileName,
} from '../../../src/reporter/shard-file.ts';
import type { ShardFile } from '../../../src/reporter/shard-file.ts';
import { main } from '../../../src/cli/main.ts';
import { fakeCliHost } from '../cli/harness.ts';

const custom = defineRule({
  id: 'custom.request-id-missing',
  defaultSeverity: 'low',
  defaultConfidence: 'high',
  scope: 'endpoint',
  options: { header: 'x-request-id' },
  docs: { title: 'No request id', why: 'w', fix: 'f', url: 'https://wiki.example.com/r' },
  check: () => [],
});

const config = (): ResolvedSecurityConfig => {
  const r = resolveConfig({
    rules: { custom: [custom] },
    normalization: { extraIdPatterns: [/^ord-\d+$/] },
  });
  if (!r.ok) throw new Error('bad config');
  return r.config;
};

const ref = (n: number): TestContextRef => ({
  testId: `t${String(n)}`,
  titlePath: [`test ${String(n)}`],
  file: `tests/f${String(n % 3)}.spec.ts`,
  line: n,
  project: 'chromium',
});

/** A finding of test `n`, as in its attachment. */
const finding = (n: number, print: string, snippet: string): Finding => ({
  ruleId: 'header.xcto-missing',
  severity: 'low',
  confidence: 'high',
  scope: 'origin',
  subject: 'https://app.test',
  location: { origin: 'https://app.test' },
  evidence: [{ kind: 'header', name: 'x', snippet }],
  message: 'm',
  fingerprint: print,
  occurrences: 1,
  firstSeen: ref(n),
  tests: [ref(n).testId],
  sources: ['browser'],
});

function shard(current: number, total: number, over: Partial<ShardFile> = {}): ShardFile {
  return {
    format: SHARD_FILE_FORMAT,
    schemaVersion: SHARD_FILE_VERSION,
    pkgVersion: '1.0.0',
    playwrightVersion: '1.57.0',
    shard: { current, total },
    runId: `r${String(current)}`,
    startedAt: `2026-11-27T10:0${String(current)}:00.000Z`,
    finishedAt: `2026-11-27T10:1${String(current)}:00.000Z`,
    mode: 'scan',
    partial: false,
    paths: {
      configDir: '.',
      configFile: 'playwright.config.ts',
      baselinePath: 'security-baseline.json',
    },
    config: configSnapshot(config()),
    scope: ['https://app.test'],
    ci: { commit: 'abc1234def', branch: 'main', buildUrl: null },
    status: 'passed',
    tests: { total: 1, passed: 1, failed: 0, flaky: 0, skipped: 0 },
    findings: [],
    coverage: emptyCoverage(),
    testsWithoutTraffic: [],
    diagnostics: [],
    authz: null,
    ...over,
  };
}

const files = (...list: ShardFile[]) =>
  list.map((s) => ({ name: shardFileName(s.shard), text: JSON.stringify(s) }));

const validate = (list: { name: string; text: string | null }[], configFound = true) =>
  validateShardSet({ files: list, configFound: () => configFound });

const codes = (set: ReturnType<typeof validate>): string[] =>
  (set.kind === 'ok' ? set.diagnostics : set.errors).map((d) => d.code);

describe('shard file (17, chapter 5)', () => {
  test('names and parsing', () => {
    expect(shardFileName({ current: 2, total: 3 })).toBe('shard-2-of-3.json');
    expect(isShardFileName('shard-2-of-3.json')).toBe(true);
    expect(isShardFileName('shard-0-of-3.json')).toBe(false);
    expect(isShardFileName('report.json')).toBe(false);
    expect(parseShardFile(JSON.stringify(shard(1, 3))).ok).toBe(true);
    expect(parseShardFile('{').ok).toBe(false);
    expect(parseShardFile(JSON.stringify({ format: 'other' }))).toEqual({
      ok: false,
      reason: 'the file is no shard file',
    });
    const { findings: _f, ...noFindings } = shard(1, 3);
    expect(parseShardFile(JSON.stringify(noFindings))).toEqual({
      ok: false,
      reason: 'fields are missing: findings',
    });
    expect(parseShardFile(JSON.stringify(shard(4, 3))).ok).toBe(false);
  });

  test('16-REQ-13 the config snapshot has no functions; the merge rebuilds the config from it', () => {
    const snapshot = configSnapshot(config());
    expect(typeof snapshot.normalization).toBe('string');
    expect(snapshot.normalization).toMatch(/^[0-9a-f]{64}$/);
    expect(snapshot.customRules).toEqual([
      expect.objectContaining({ id: 'custom.request-id-missing', docs: expect.any(Object) }),
    ]);
    expect(JSON.stringify(snapshot)).not.toContain('check');
    const rebuilt = configFromSnapshot(JSON.parse(JSON.stringify(snapshot)) as typeof snapshot);
    expect(rebuilt.rules['custom.request-id-missing']?.enabled).toBe(true);
    expect(rebuilt.customRules[0]?.docs.url).toBe('https://wiki.example.com/r');
    expect(rebuilt.gate).toEqual(config().gate);
    // Another normalization gives another fingerprint (MERGE_SHARD_MISMATCH).
    const other = resolveConfig({ normalization: { extraIdPatterns: [/^x-\d+$/] } });
    if (!other.ok) throw new Error('bad config');
    expect(configSnapshot(other.config).normalization).not.toBe(snapshot.normalization);
  });
});

describe('17-AC-04 validation of the shard set (17-REQ-10)', () => {
  test('no shard files: MERGE_NO_SHARD_FILES', () => {
    const set = validate([{ name: 'report.json', text: '{}' }]);
    expect(set.kind).toBe('none');
    expect(codes(set)).toEqual(['MERGE_NO_SHARD_FILES']);
  });

  test('an unreadable or foreign file: MERGE_SHARD_INVALID, the file is skipped', () => {
    const set = validate([
      ...files(shard(1, 2), shard(2, 2)),
      { name: 'shard-3-of-3.json', text: 'not json' },
    ]);
    // The skipped file is reported; the other two form a complete set of 2.
    expect(set.kind).toBe('ok');
    expect(codes(set)).toEqual(['MERGE_SHARD_INVALID']);
    expect(validate([{ name: 'shard-1-of-1.json', text: null }]).kind).toBe('fatal');
  });

  test.each([
    ['pkgVersion', { pkgVersion: '2.0.0' }],
    ['playwrightVersion', { playwrightVersion: '1.58.0' }],
    ['mode', { mode: 'baseline' as const }],
    ['config', { config: { ...configSnapshot(config()), preset: 'strict' as const } }],
    [
      'paths',
      { paths: { configDir: 'e2e', configFile: 'playwright.config.ts', baselinePath: 'b.json' } },
    ],
  ])('a different %s: MERGE_SHARD_MISMATCH, no evaluation', (field, over) => {
    const set = validate(files(shard(1, 2), shard(2, 2, over as Partial<ShardFile>)));
    expect(set.kind).toBe('fatal');
    expect(codes(set)).toEqual(['MERGE_SHARD_MISMATCH']);
    expect(set.kind === 'fatal' ? set.errors[0]?.message : '').toContain(`(${field})`);
  });

  test('a different number of shards: MERGE_SHARD_MISMATCH', () => {
    const set = validate(files(shard(1, 2), shard(2, 3)));
    expect(codes(set)).toEqual(['MERGE_SHARD_MISMATCH']);
  });

  test('two files of one shard: MERGE_SHARD_DUPLICATE', () => {
    const set = validate([
      ...files(shard(1, 2), shard(2, 2)),
      { name: 'shard-2-of-2 (1).json', text: JSON.stringify(shard(2, 2)) },
      { name: 'shard-02-of-2.json', text: JSON.stringify(shard(2, 2)) },
    ]);
    // "shard-2-of-2 (1).json" is not a shard file name; "shard-02" is not either.
    expect(set.kind).toBe('ok');
    const dup = validateShardSet({
      files: [
        { name: 'shard-1-of-2.json', text: JSON.stringify(shard(1, 2)) },
        { name: 'shard-2-of-2.json', text: JSON.stringify(shard(2, 2)) },
        { name: 'shard-3-of-3.json', text: JSON.stringify(shard(2, 2)) },
      ],
      configFound: () => true,
    });
    expect(codes(dup)).toEqual(['MERGE_SHARD_DUPLICATE']);
  });

  test('missing numbers: MERGE_SHARD_MISSING with the shards, the merge goes on', () => {
    const set = validate(files(shard(1, 3), shard(3, 3)));
    expect(set.kind).toBe('ok');
    expect(set.kind === 'ok' ? set.missing : []).toEqual([2]);
    expect(codes(set)).toEqual(['MERGE_SHARD_MISSING']);
    expect(set.kind === 'ok' ? set.diagnostics[0]?.message : '').toContain('shard 2/3 is missing');
  });

  test('different commits: the warning MERGE_SHARDS_DIFFERENT_COMMIT', () => {
    const set = validate(
      files(
        shard(1, 2),
        shard(2, 2, { ci: { commit: 'fff0000aaa', branch: null, buildUrl: null } }),
      ),
    );
    expect(set.kind).toBe('ok');
    expect(set.kind === 'ok' ? set.diagnostics.map((d) => [d.code, d.level]) : []).toEqual([
      ['MERGE_SHARDS_DIFFERENT_COMMIT', 'warn'],
    ]);
  });

  test('the config of the shards is not below the working directory: MERGE_WRONG_DIRECTORY', () => {
    const set = validate(files(shard(1, 1)), false);
    expect(set.kind).toBe('fatal');
    expect(codes(set)).toEqual(['MERGE_WRONG_DIRECTORY']);
  });
});

describe('combination (17-REQ-11, 17-REQ-12)', () => {
  // Five tests with findings of two fingerprints and more evidence than kept.
  const all = [1, 2, 3, 4, 5].flatMap((n) => [
    finding(n, 'a', `a${String(n)}`),
    ...(n % 2 === 0 ? [finding(n, 'b', `b${String(n)}`)] : []),
  ]);

  test.each([
    [[[1, 2, 3, 4, 5]]],
    [
      [
        [1, 3, 5],
        [2, 4],
      ],
    ],
    [[[5], [4, 1], [3, 2]]],
    [[[2], [5, 3], [1, 4]]],
  ])('the findings do not depend on the split %j', (split) => {
    const shards = split.map((tests, i) =>
      shard(i + 1, split.length, {
        findings: all.filter((f) => tests.includes(f.firstSeen.line)),
      }),
    );
    const merged = combineShards(shards);
    expect(dedupeRun(merged.data.findings)).toEqual(dedupeRun(all));
    expect(merged.tests.size).toBe(5);
  });

  test('coverage, tests without traffic, test results and the shard list', () => {
    const a = emptyCoverage();
    a.responses = 3;
    a.endpoints['GET /'] = 2;
    const b = emptyCoverage();
    b.responses = 4;
    b.endpoints['GET /'] = 1;
    const merged = combineShards([
      shard(1, 2, { coverage: a, testsWithoutTraffic: [ref(9)], findings: [finding(1, 'a', 'x')] }),
      shard(2, 2, {
        coverage: b,
        status: 'failed',
        ci: { commit: null, branch: null, buildUrl: 'https://ci/2' },
      }),
    ]);
    expect(merged.data.coverage.responses).toBe(7);
    expect(merged.data.coverage.endpoints).toEqual({ 'GET /': 3 });
    expect(merged.data.testsWithoutTraffic).toEqual([ref(9)]);
    expect(merged.data.testsPassed).toBe(false);
    expect(merged.list).toEqual([
      {
        index: 1,
        runId: 'r1',
        startedAt: '2026-11-27T10:01:00.000Z',
        finishedAt: '2026-11-27T10:11:00.000Z',
        tests: 1,
        findings: 1,
        responses: 3,
        buildUrl: null,
      },
      {
        index: 2,
        runId: 'r2',
        startedAt: '2026-11-27T10:02:00.000Z',
        finishedAt: '2026-11-27T10:12:00.000Z',
        tests: 1,
        findings: 0,
        responses: 4,
        buildUrl: 'https://ci/2',
      },
    ]);
  });
});

describe('modes and the binary (17-REQ-06, 17-REQ-09)', () => {
  test('17-AC-06 PW_SEC_MODE=merge in the test command is MODE_INVALID with the merge command', () => {
    const mode = readMode({ PW_SEC_MODE: 'merge' });
    expect(mode.ok).toBe(false);
    const issue = mode.ok ? undefined : mode.issues[0];
    expect(issue?.code).toBe('MODE_INVALID');
    expect(issue?.hint).toContain('PW_SEC_MODE=merge npx pw-sec');
    expect(isMergeMode({ PW_SEC_MODE: ' Merge ' })).toBe(true);
    expect(isMergeMode({})).toBe(false);
  });

  test('--shard is no filter (17-REQ-06); --grep still is', () => {
    const argv = (...a: string[]) => ['node', 'playwright', 'test', ...a];
    expect(isPartialRun(undefined, undefined, argv('--shard=2/3'))).toBe(false);
    expect(isPartialRun(undefined, undefined, argv('--shard', '2/3'))).toBe(false);
    expect(isPartialRun(undefined, undefined, argv('--shard=2/3', '--grep', 'x'))).toBe(true);
  });

  test('npx pw-sec with PW_SEC_MODE=merge merges; without shard files it ends with code 3 and no outcome', async () => {
    const cwd = mkdtempSync(join(tmpdir(), 'pw-sec-merge-'));
    const fake = fakeCliHost({ cwd, env: { PW_SEC_MODE: 'merge', NO_COLOR: '1' } });
    expect(await main([], fake.host)).toBe(3);
    expect(fake.stderr.join('')).toContain('MERGE_NO_SHARD_FILES');
    expect(existsSync(join(cwd, 'reports/pw-sec/outcome.json'))).toBe(false);
  });

  test('a mismatch writes outcome.json with code 3 and no report', () => {
    const cwd = mkdtempSync(join(tmpdir(), 'pw-sec-merge-'));
    writeFileSync(join(cwd, 'playwright.config.ts'), 'export default {};\n');
    const dir = join(cwd, 'reports/pw-sec');
    mkdirSync(dir, { recursive: true });
    for (const f of files(shard(1, 2), shard(2, 2, { mode: 'baseline' }))) {
      writeFileSync(join(dir, f.name), f.text);
    }
    const out: string[] = [];
    const err: string[] = [];
    const code = runMerge({
      cwd,
      env: { NO_COLOR: '1' },
      stdout: { write: (t: string) => out.push(t) },
      stderr: { write: (t: string) => err.push(t) },
    });
    expect(code).toBe(3);
    expect(err.join('')).toContain('MERGE_SHARD_MISMATCH');
    expect(existsSync(join(dir, 'outcome.json'))).toBe(true);
    expect(existsSync(join(dir, 'report.json'))).toBe(false);
  });
});
