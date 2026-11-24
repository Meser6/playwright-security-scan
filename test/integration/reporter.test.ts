// The reporter on real runs (04, 08, 09): banner, summary, report.json, outcome.json, baseline.
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, test } from 'vitest';
import { startShop } from '../app/shop.ts';
import type { Shop } from '../app/shop.ts';
import { RUN_TIMEOUT, startHarness } from './harness.ts';
import type { Harness } from './harness.ts';

let harness: Harness;
const shops: Shop[] = [];

beforeAll(async () => {
  harness = await startHarness();
}, RUN_TIMEOUT);

afterAll(async () => {
  await Promise.all(shops.map((s) => s.close()));
  await harness?.close();
});

async function shop(vulns: string[]): Promise<Shop> {
  const s = await startShop(vulns);
  shops.push(s);
  return s;
}

const env = (s: Shop, mode: string) => ({
  PW_SEC_MODE: mode,
  APP_URL: s.url,
  PARTNER_URL: s.partnerUrl,
});

describe('reporter (04, 08, 09)', () => {
  test(
    '03-AC-01 without config and baseURL the first scan ends with NO_TRAFFIC and the hint',
    async () => {
      const run = await harness.run(harness.copy('no-base'), { env: { PW_SEC_MODE: 'scan' } });
      expect(run.outcome?.code, run.output).toBe(4);
      expect(run.outcome?.name).toBe('NO_TRAFFIC');
      expect(run.status).toBe(1);
      expect(run.output).toContain('set `use.baseURL` or `scope.origins`');
      expect(run.output).toContain('pw-sec · mode: scan · passive only');
    },
    RUN_TIMEOUT,
  );

  test(
    '08-AC-01 S-04: after a baseline run an unchanged scan ends with code 0; S-05: a session cookie without HttpOnly fails with one new finding',
    async () => {
      const dir = harness.copy('shop');
      const before = await shop([
        'header.csp-unsafe',
        'cookie.samesite-none',
        'disclosure.server-version',
      ]);
      const baseline = await harness.run(dir, { env: env(before, 'baseline') });
      expect(baseline.outcome?.code, baseline.output).toBe(0);
      expect(baseline.baseline).not.toBeNull();
      expect(baseline.output).toContain('security-baseline.json');
      expect(baseline.output).toMatch(/\+ header\.csp-unsafe \| https:\/\/localhost:\d+/);
      expect(baseline.output).toContain('Review the new entries');
      const entries = Object.keys(
        (JSON.parse(baseline.baseline ?? '{}') as { findings: object }).findings,
      );
      expect(entries.length).toBeGreaterThanOrEqual(3);

      const scan = await harness.run(dir, { env: env(before, 'scan') });
      expect(scan.outcome, scan.output).toMatchObject({ code: 0, name: 'OK', newBlocking: 0 });
      expect(scan.status).toBe(0);
      expect(scan.report?.findings.every((f) => f.classification === 'accepted')).toBe(true);

      // S-05: the same app plus one switch. It listens on a new port, so the origin in the
      // committed baseline is rewritten to it, as if the app had not moved.
      const after = await shop([
        'header.csp-unsafe',
        'cookie.samesite-none',
        'disclosure.server-version',
        'cookie.no-httponly',
      ]);
      const rewritten = (baseline.baseline ?? '')
        .replaceAll(before.url, after.url)
        .replaceAll(new URL(before.url).host, new URL(after.url).host);
      writeFileSync(join(dir, 'security-baseline.json'), rewritten);
      const fail = await harness.run(dir, { env: env(after, 'scan') });
      expect(fail.outcome, fail.output).toMatchObject({
        code: 1,
        name: 'NEW_FINDINGS',
        newBlocking: 1,
      });
      expect(fail.status).toBe(1);
      const blocking = fail.report?.findings.filter((f) => f.blocking) ?? [];
      expect(blocking.map((f) => f.fingerprint)).toEqual([
        `cookie.no-httponly|cookie|sid@localhost`,
      ]);
      expect(blocking[0]?.firstSeen.file).toMatch(/^tests\/(api|e2e)\.spec\.ts$/);
      expect(fail.output).toMatch(/✘ cookie\.no-httponly\s+medium\/(high|low)\s+sid@localhost/);
      expect(fail.output).toContain('first seen: tests/');
      expect(fail.output).toContain('→ accept: PW_SEC_MODE=baseline npx playwright test');
      const summary = fail.output.slice(
        fail.output.indexOf('pw-sec · ') === -1 ? 0 : fail.output.lastIndexOf('pw-sec · '),
      );
      expect(summary.trim().split('\n').length).toBeLessThanOrEqual(30);
    },
    RUN_TIMEOUT * 3,
  );

  test(
    '08-AC-02 an expired entry that still occurs fails the scan with code 2',
    async () => {
      const dir = harness.copy('shop');
      const s = await shop(['header.csp-unsafe']);
      await harness.run(dir, { env: env(s, 'baseline') });
      const file = join(dir, 'security-baseline.json');
      const doc = JSON.parse(readFileSync(file, 'utf8')) as {
        findings: Record<string, Record<string, string>>;
      };
      const yesterday = new Date(Date.now() - 86_400_000).toISOString().slice(0, 10);
      for (const [print, entry] of Object.entries(doc.findings)) {
        if (print.startsWith('header.csp-unsafe|')) {
          entry.until = yesterday;
          entry.note = 'temporary';
        }
      }
      writeFileSync(file, JSON.stringify(doc, null, 2));
      const run = await harness.run(dir, { env: env(s, 'scan') });
      expect(run.outcome, run.output).toMatchObject({
        code: 2,
        name: 'BASELINE_EXPIRED',
        expired: 1,
      });
    },
    RUN_TIMEOUT * 2,
  );

  test(
    '04-AC-02 a baseline run with --grep keeps the entries of tests it did not run',
    async () => {
      const dir = harness.copy('shop');
      const s = await shop(['disclosure.stack-trace', 'header.csp-unsafe']);
      const full = await harness.run(dir, { env: env(s, 'baseline') });
      const before = Object.keys(
        (JSON.parse(full.baseline ?? '{}') as { findings: object }).findings,
      );
      expect(before.some((p) => p.startsWith('disclosure.stack-trace|'))).toBe(true);
      const partial = await harness.run(dir, {
        env: env(s, 'baseline'),
        args: ['--grep', 'home page'],
      });
      const after = Object.keys(
        (JSON.parse(partial.baseline ?? '{}') as { findings: object }).findings,
      );
      expect(after).toEqual(before);
      expect(partial.report?.diagnostics.map((d) => d.code)).toContain('PARTIAL_RUN');
    },
    RUN_TIMEOUT * 2,
  );

  test(
    '09-REQ-06 and 09-REQ-10 a scan writes results.sarif and junit.xml next to report.json',
    async () => {
      const s = await shop(['cookie.no-httponly', 'header.csp-unsafe']);
      const run = await harness.run(harness.copy('shop'), { env: env(s, 'scan') });
      const dir = join(run.dir, 'reports/pw-sec');
      expect(existsSync(join(dir, 'results.sarif')), run.output).toBe(true);
      const sarif = JSON.parse(readFileSync(join(dir, 'results.sarif'), 'utf8')) as {
        runs: { results: { ruleId: string }[] }[];
      };
      expect(sarif.runs[0]?.results.map((r) => r.ruleId)).toEqual(
        expect.arrayContaining(['cookie.no-httponly', 'header.csp-unsafe']),
      );
      const junit = readFileSync(join(dir, 'junit.xml'), 'utf8');
      expect(junit).toContain('<testsuites name="pw-sec"');
      expect(junit).toContain('classname="pw-sec.cookie.cookie.no-httponly"');
    },
    RUN_TIMEOUT,
  );
});
