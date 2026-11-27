// Custom rules on real runs (16-AC-01, 16-AC-02, 16-AC-04, 16-AC-06): test/projects/shop with
// the rules of security-rules.ts.
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, test } from 'vitest';
import { SECRETS, startShop } from '../app/shop.ts';
import type { Shop } from '../app/shop.ts';
import { RUN_TIMEOUT, startHarness } from './harness.ts';
import type { Harness, ProjectRun } from './harness.ts';

let harness: Harness;
const shops: Shop[] = [];

beforeAll(async () => {
  harness = await startHarness();
}, RUN_TIMEOUT);

afterAll(async () => {
  await Promise.all(shops.map((s) => s.close()));
  await harness?.close();
});

async function shop(vulns: string[] = []): Promise<Shop> {
  const s = await startShop(vulns);
  shops.push(s);
  return s;
}

const env = (s: Shop, mode: string, extra: Record<string, string> = {}) => ({
  PW_SEC_MODE: mode,
  APP_URL: s.url,
  PARTNER_URL: s.partnerUrl,
  SHOP_CUSTOM_RULES: '1',
  ...extra,
});

function filesUnder(dir: string): string[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? filesUnder(path) : [path];
  });
}

/** Findings of custom.request-id-missing on the API of the app (the e2e tests fetch more). */
const customFindings = (run: ProjectRun): string[] =>
  (run.report?.findings ?? [])
    .filter((f) => f.ruleId === 'custom.request-id-missing' && f.subject.startsWith('GET /api/'))
    .map((f) => `${f.subject} ${f.classification}${f.blocking ? ' blocking' : ''}`)
    .sort();

describe('custom rules (16)', () => {
  test(
    '16-AC-01 16-AC-04 16-AC-06 a custom rule finds, goes into the baseline, blocks and is in every report',
    async () => {
      const dir = harness.copy('shop');
      const secure = await shop();

      const baseline = await harness.run(dir, { env: env(secure, 'baseline') });
      expect(baseline.status, baseline.output).toBe(0);
      expect(baseline.output).toContain('(preset recommended, 2 custom)');
      const entries = JSON.parse(baseline.baseline ?? '{}') as {
        findings: Record<string, { ruleId: string }>;
      };
      expect(Object.keys(entries.findings)).toContain(
        'custom.request-id-missing|endpoint|GET /api/token',
      );
      expect(Object.keys(entries.findings)).not.toContain(
        'custom.request-id-missing|endpoint|GET /api/me',
      );

      const scan = await harness.run(dir, { env: env(secure, 'scan') });
      expect(scan.outcome?.code, scan.output).toBe(0);
      expect(customFindings(scan)).toEqual(['GET /api/token accepted']);

      // The header disappears from another endpoint: a new finding fails the run.
      const regressed = await shop(['custom.request-id-missing']);
      const failed = await harness.run(dir, { env: env(regressed, 'scan') });
      expect(failed.outcome?.code, failed.output).toBe(1);
      expect(failed.status).toBe(1);
      expect(customFindings(failed)).toEqual([
        'GET /api/me new blocking',
        'GET /api/token accepted',
      ]);

      // 16-AC-04: SARIF, JUnit and HTML.
      const reports = join(failed.dir, 'reports/pw-sec');
      const sarif = JSON.parse(readFileSync(join(reports, 'results.sarif'), 'utf8')) as {
        runs: { tool: { driver: { rules: { id: string; properties: { tags: string[] } }[] } } }[];
      };
      const rule = sarif.runs[0]?.tool.driver.rules.find(
        (r) => r.id === 'custom.request-id-missing',
      );
      expect(rule?.properties.tags).toContain('custom');
      const junit = readFileSync(join(reports, 'junit.xml'), 'utf8');
      expect(junit).toMatch(/<testsuite name="custom" tests="\d+" failures="1"/);
      const html = readFileSync(join(reports, 'report.html'), 'utf8');
      expect(html).toContain(
        '<span class="key">custom.request-id-missing</span></a> <span class="src">custom</span>',
      );
      expect(html).toContain('https://wiki.example.com/security/request-id');

      // 16-AC-06: the Set-Cookie evidence of custom.login-cookies is redacted.
      const login = failed.report?.findings.find((f) => f.ruleId === 'custom.login-cookies');
      expect(login?.evidence.length).toBeGreaterThan(0);
      for (const run of [baseline, scan, failed]) {
        const files = [
          ...filesUnder(join(run.dir, 'reports')),
          ...filesUnder(join(run.dir, 'test-results')),
          join(run.dir, 'results.json'),
          join(run.dir, 'security-baseline.json'),
        ];
        for (const file of files) {
          const text = readFileSync(file, 'latin1');
          for (const [name, secret] of Object.entries(SECRETS)) {
            expect(text.includes(secret), `${name} in ${file}`).toBe(false);
          }
        }
      }
    },
    RUN_TIMEOUT,
  );

  test(
    '16-AC-02 a throwing custom rule: the tests pass, TOOL_ERROR with CUSTOM_RULE_ERROR and the rule id',
    async () => {
      const s = await shop();
      const run = await harness.run(harness.copy('shop'), {
        env: env(s, 'scan', { SHOP_CUSTOM_THROW: '1' }),
      });
      expect(
        run.results.filter((r) => r.status !== 'passed').map((r) => r.title),
        run.output,
      ).toEqual([]);
      expect(run.outcome?.code).toBe(3);
      expect(run.outcome?.name).toBe('TOOL_ERROR');
      const diagnostic = run.report?.diagnostics.find((d) => d.code === 'CUSTOM_RULE_ERROR');
      expect(diagnostic?.level).toBe('error');
      expect(diagnostic?.message).toContain('custom rule custom.broken threw');
      expect(diagnostic?.message).toContain('this custom rule fails on purpose');
      // The first stack line of the user's file, relative to the directory of the run.
      expect(diagnostic?.message).toMatch(/\(at Object\.check \(security-rules\.ts:\d+:\d+\)\)$/);
      expect(run.output).toContain('CUSTOM_RULE_ERROR');
      expect(run.output).toContain('custom.broken');
      // The other rules still ran.
      expect(customFindings(run)).toEqual(['GET /api/token new blocking']);
    },
    RUN_TIMEOUT,
  );
});
