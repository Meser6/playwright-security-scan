// APIRequestContext traffic on real Playwright (15). Runs on dist/: `pnpm build` first.
import { afterAll, beforeAll, describe, expect, test } from 'vitest';
import { dedupeRun } from '../../src/core/fingerprint/index.ts';
import { RUN_TIMEOUT, startHarness } from './harness.ts';
import type { Harness, ProjectRun, TestResult } from './harness.ts';

let harness: Harness;
let scan: ProjectRun;
let plain: ProjectRun;

const byTitle = (run: ProjectRun, title: string): TestResult => {
  const found = run.results.find((r) => r.title === title);
  if (found === undefined) throw new Error(`no test "${title}" in:\n${run.output}`);
  return found;
};

beforeAll(async () => {
  harness = await startHarness();
  scan = await harness.run(harness.copy('api'), { env: { PW_SEC_MODE: 'scan' } });
  plain = await harness.run(harness.copy('api'));
}, RUN_TIMEOUT * 2);

afterAll(async () => {
  await harness?.close();
});

describe('API traffic (15)', () => {
  test('every test passes with and without the scan', () => {
    expect(
      scan.results.filter((r) => r.status !== 'passed').map((r) => r.title),
      scan.output,
    ).toEqual([]);
    expect(
      plain.results.filter((r) => r.status !== 'passed').map((r) => r.title),
      plain.output,
    ).toEqual([]);
    expect(scan.results).toHaveLength(9);
  });

  test('15-AC-01 API-only tests give findings of the API rules', () => {
    const a = byTitle(scan, 'API GET item').attachment;
    expect(a?.coverage.apiResponses).toBe(1);
    expect(a?.coverage.endpoints).toEqual({ 'GET /api/items/:id': 1 });
    expect(a?.findings.map((f) => [f.ruleId, f.sources])).toContainEqual([
      'header.xcto-missing',
      ['api'],
    ]);
    const secret = byTitle(scan, 'API fetch config with a secret').attachment?.findings.find(
      (f) => f.ruleId === 'data.secret-in-asset',
    );
    expect(secret?.fingerprint).toBe(
      'data.secret-in-asset|endpoint|GET /api/config|aws-access-key',
    );
  });

  test('15-AC-02 the same missing nosniff from a UI test and an API test is one finding from both sources', () => {
    const findings = [
      byTitle(scan, 'API GET item'),
      byTitle(scan, 'UI test on the same endpoint'),
    ].flatMap((r) => r.attachment?.findings ?? []);
    const merged = dedupeRun(findings).filter((f) => f.ruleId === 'header.xcto-missing');
    expect(merged).toHaveLength(1);
    expect(merged[0]?.sources).toEqual(['browser', 'api']);
  });

  test('15-AC-03 an API call that times out ends the test with the same error as without the package', () => {
    expect(byTitle(scan, 'API timeout gives the original error').status).toBe('passed');
    expect(byTitle(plain, 'API timeout gives the original error').status).toBe('passed');
    expect(
      byTitle(scan, 'API timeout gives the original error').attachment?.coverage.bodiesSkipped[
        'request-failed'
      ],
    ).toBe(1);
  });

  test('15-AC-04 without PW_SEC_MODE the request methods are not wrapped', () => {
    expect(byTitle(plain, 'request methods are wrapped only in scan mode').status).toBe('passed');
    expect(plain.results.every((r) => r.attachment === null)).toBe(true);
  });

  test('15-REQ-06 an API origin out of scope is counted and reported once', () => {
    const a = byTitle(scan, 'API origin out of scope').attachment;
    expect(a?.coverage.outOfScope).toBe(1);
    expect(a?.coverage.apiResponses).toBe(0);
    expect(a?.diagnostics.map((d) => d.code)).toEqual(['API_ORIGIN_OUT_OF_SCOPE']);
  });

  test('15-REQ-01 page.request and trackRequestContext() contexts are scanned', () => {
    expect(byTitle(scan, 'page.request is scanned').attachment?.coverage.apiResponses).toBe(1);
    expect(
      byTitle(scan, 'trackRequestContext scans a context from playwright.request').attachment
        ?.coverage.apiResponses,
    ).toBe(1);
  });

  test('request headers of the call are in the record (15, chapter 4)', () => {
    expect(byTitle(scan, 'API POST order').attachment?.coverage.endpoints).toEqual({
      'POST /api/orders': 1,
    });
  });
});

describe('compatibility with the perf package (01-REQ-09)', () => {
  let securityOnly: ProjectRun;
  let perfOnly: ProjectRun;
  let securityOuter: ProjectRun;
  let perfOuter: ProjectRun;

  beforeAll(async () => {
    securityOnly = await harness.run(harness.copy('perf-chain'), { env: { PW_SEC_MODE: 'scan' } });
    perfOnly = await harness.run(harness.copy('perf-chain'), {
      env: { PW_PERF_MODE: 'test', PW_PERF_PASSES: '1' },
    });
    const both = { PW_SEC_MODE: 'scan', PW_PERF_MODE: 'test', PW_PERF_PASSES: '1' };
    securityOuter = await harness.run(harness.copy('perf-chain'), { env: both });
    perfOuter = await harness.run(harness.copy('perf-chain'), {
      env: { ...both, ORDER: 'perf-outer' },
    });
  }, RUN_TIMEOUT * 4);

  const prints = (run: ProjectRun): string[] =>
    run.results
      .flatMap(
        (r) =>
          r.attachment?.findings.map((f) => `${r.title}: ${f.fingerprint} x${f.occurrences}`) ?? [],
      )
      .sort();

  test('15-AC-05 with the perf package each API call gives one perf sample and one security record', () => {
    for (const run of [securityOuter, perfOuter]) {
      const api = byTitle(run, 'API calls');
      expect(api.status, run.output).toBe('passed');
      expect(api.perf?.apiRequests).toHaveLength(3);
      expect(api.attachment?.coverage.apiResponses).toBe(3);
    }
  });

  test('01-AC-02 both chain orders give the same findings and measurements as each package alone', () => {
    expect(prints(securityOnly).length).toBeGreaterThan(0);
    expect(prints(securityOuter)).toEqual(prints(securityOnly));
    expect(prints(perfOuter)).toEqual(prints(securityOnly));
    const samples = (run: ProjectRun) =>
      run.results
        .map(
          (r) => `${r.title}: ${r.perf?.apiRequests.length ?? 0}/${r.perf?.requests.length ?? 0}`,
        )
        .sort();
    expect(samples(perfOnly).every((s) => !s.endsWith(': 0/0'))).toBe(true);
    expect(samples(securityOuter)).toEqual(samples(perfOnly));
    expect(samples(perfOuter)).toEqual(samples(perfOnly));
  });
});
