// Browser collector on real Playwright (05). Runs on dist/: `pnpm build` first.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, test } from 'vitest';
import { SECRETS } from '../app/server.ts';
import { filesUnder, RUN_TIMEOUT, startHarness } from './harness.ts';
import type { Harness, ProjectRun, TestResult } from './harness.ts';

let harness: Harness;
let scan: ProjectRun;
let plain: ProjectRun;

const byTitle = (run: ProjectRun, title: string): TestResult => {
  const found = run.results.find((r) => r.title === title);
  if (found === undefined) throw new Error(`no test "${title}" in:\n${run.output}`);
  return found;
};
const ruleIds = (r: TestResult): string[] =>
  (r.attachment?.findings ?? []).map((f) => f.ruleId).sort();

beforeAll(async () => {
  harness = await startHarness();
  const dir = harness.copy('collector');
  scan = await harness.run(dir, { env: { PW_SEC_MODE: 'scan' } });
  const dir2 = harness.copy('collector');
  plain = await harness.run(dir2, { args: ['--grep', 'listeners|page with'] });
}, RUN_TIMEOUT * 2);

afterAll(async () => {
  await harness?.close();
});

describe('browser collector (05)', () => {
  test('every test passes with and without the scan (P-08)', () => {
    expect(scan.results.length, scan.output).toBe(107);
    expect(
      scan.results.filter((r) => r.status !== 'passed').map((r) => r.title),
      scan.output,
    ).toEqual([]);
    expect(
      plain.results.filter((r) => r.status !== 'passed').map((r) => r.title),
      plain.output,
    ).toEqual([]);
  });

  test('05-AC-01 without PW_SEC_MODE there are no listeners, bindings or attachments (P-02)', () => {
    expect(byTitle(plain, 'listeners and bindings only in scan mode').status).toBe('passed');
    expect(plain.results.every((r) => r.attachment === null)).toBe(true);
    expect(byTitle(scan, 'listeners and bindings only in scan mode').attachment).not.toBeNull();
  });

  test('records of the page, its script and the API call are analysed', () => {
    const a = byTitle(scan, 'page with a script and an API call').attachment;
    expect(a?.coverage.documents).toBe(1);
    expect(Object.keys(a?.coverage.endpoints ?? {}).sort()).toEqual([
      'GET /api/items/:id',
      'GET /page',
      'GET /static/app.3f2a9c1b.js',
    ]);
    expect(a?.coverage.assets).toEqual([expect.stringMatching(/\/static\/app\.\*\.js$/)]);
    expect(ruleIds(byTitle(scan, 'page with a script and an API call'))).toEqual(
      expect.arrayContaining(['data.secret-in-asset', 'header.xcto-missing']),
    );
    const secret = a?.findings.find((f) => f.ruleId === 'data.secret-in-asset');
    expect(secret?.fingerprint).toMatch(
      /^data\.secret-in-asset\|asset\|http:\/\/127\.0\.0\.1:\d+\/static\/app\.\*\.js\|aws-access-key$/,
    );
    expect(secret?.evidence[0]?.snippet).toContain('AKIA…[sha256:');
  });

  test('mocked responses are not analysed (05-REQ-26)', () => {
    const a = byTitle(scan, 'mocked responses are skipped').attachment;
    expect(a?.coverage.bodiesSkipped.mocked).toBe(1);
    expect(a?.coverage.endpoints['GET /api/items/:id']).toBeUndefined();
  });

  test('05-AC-02 a 5 MB bundle in 100 tests is read once per worker and analysed up to 1 MB', () => {
    const bundles = scan.results.filter((r) => r.title.startsWith('bundle '));
    expect(bundles).toHaveLength(100);
    const analyzed = bundles.reduce((n, r) => n + (r.attachment?.coverage.bodiesAnalyzed ?? 0), 0);
    const cached = bundles.reduce(
      (n, r) => n + (r.attachment?.coverage.bodiesSkipped.cached ?? 0),
      0,
    );
    // The document of each test has no body rule input other than secrets: 100 documents + 1 bundle.
    expect(analyzed).toBe(101);
    expect(cached).toBe(99);
    for (const r of bundles) {
      const secrets =
        r.attachment?.findings.filter((f) => f.ruleId === 'data.secret-in-asset') ?? [];
      expect(secrets.map((f) => f.discriminator)).toEqual(['aws-access-key']);
      expect(secrets[0]?.occurrences).toBe(1);
    }
  });

  test('05-AC-03 a context closed while a body is read: test green, BODY_READ_FAILED', () => {
    const r = byTitle(scan, 'context closed while a body is read');
    expect(r.status).toBe('passed');
    expect(r.attachment?.diagnostics.map((d) => d.code)).toContain('BODY_READ_FAILED');
  });

  test('Web Storage is scanned at the end of the test (05-REQ-23)', () => {
    const r = byTitle(scan, 'token in localStorage');
    expect(r.attachment?.coverage.storageOrigins).toEqual([harness.app.url]);
    const f = r.attachment?.findings.find((x) => x.ruleId === 'data.token-in-storage');
    expect(f?.subject).toBe(`auth_token@${harness.app.url}`);
    expect(f?.evidence[0]?.snippet).toMatch(/^eyJ…\[jwt alg=HS256 sha256:[0-9a-f]{6}\]$/);
  });

  test('worker-scoped contexts registered with trackContext() are scanned (05-REQ-02)', () => {
    const r = byTitle(scan, 'worker-scoped context registered with trackContext()');
    expect(r.attachment?.coverage.endpoints['GET /storage']).toBe(1);
    expect(ruleIds(r)).toContain('data.token-in-storage');
  });

  test('05-AC-04 the localStorage token is in no file under reports/, test-results/ or the JSON report', () => {
    const files = [
      ...filesUnder(join(scan.dir, 'reports')),
      ...filesUnder(join(scan.dir, 'test-results')),
      join(scan.dir, 'results.json'),
    ];
    for (const file of files) {
      const text = readFileSync(file, 'latin1');
      for (const secret of Object.values(SECRETS)) {
        expect(text.includes(secret), `${secret} in ${file}`).toBe(false);
      }
    }
  });
});
