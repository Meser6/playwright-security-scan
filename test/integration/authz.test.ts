// Authorization tests on the reference app (18, chapter 11): deliberate IDOR, an endpoint without
// a session check and an admin endpoint open to customers, and their secure counterparts.
import { spawn } from 'node:child_process';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, test } from 'vitest';
import { AUTHZ_SWITCHES, AUTHZ_USERS, SECRETS, startShop } from '../app/shop.ts';
import type { Shop } from '../app/shop.ts';
import type { RunReport } from '../../src/core/types/index.ts';
import { filesUnder, ROOT, RUN_TIMEOUT, startHarness } from './harness.ts';
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

async function shop(vulns: readonly string[]): Promise<Shop> {
  const s = await startShop(vulns);
  shops.push(s);
  return s;
}

function run(
  s: Shop,
  options: { env?: Record<string, string>; args?: string[]; dir?: string } = {},
): Promise<ProjectRun> {
  return harness.run(options.dir ?? harness.copy('authz'), {
    env: {
      PW_SEC_MODE: 'scan',
      AUTHZ: '1',
      APP_URL: s.url,
      PARTNER_URL: s.partnerUrl,
      ...options.env,
    },
    ...(options.args === undefined ? {} : { args: options.args }),
  });
}

const authzFindings = (r: ProjectRun): string[] =>
  (r.report?.findings ?? [])
    .filter((f) => f.ruleId.startsWith('authz.'))
    .map((f) => f.fingerprint)
    .sort();

const passed = (r: ProjectRun): void => {
  expect(
    r.results.filter((t) => t.status !== 'passed').map((t) => t.title),
    r.output,
  ).toEqual([]);
};

/** `PW_SEC_MODE=merge npx pw-sec` in `dir` with the given shard files; the merged report. */
function merge(dir: string, shards: Record<string, string>): Promise<Partial<RunReport>> {
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
    child.on('error', reject);
    child.on('close', () => {
      try {
        resolve(JSON.parse(readFileSync(join(reports, 'report.json'), 'utf8')) as RunReport);
      } catch (error) {
        reject(error instanceof Error ? error : new Error(String(error)));
      }
    });
  });
}

describe('authorization tests (18)', () => {
  test(
    '18-AC-01 three deliberate bugs give exactly three findings, the secure mode none',
    async () => {
      const vulnerable = await shop(AUTHZ_SWITCHES);
      const bad = await run(vulnerable);
      passed(bad);
      // The base origin has no label in endpoint keys (07, chapter 2.1).
      const key = (path: string): string => `GET ${path}`;
      expect(authzFindings(bad), bad.output).toEqual([
        `authz.horizontal|endpoint|${key('/api/invoices/:id')}|customer->customer`,
        `authz.unauthenticated-access|endpoint|${key('/api/me/orders')}|customer->anonymous`,
        `authz.vertical|endpoint|${key('/api/admin/users')}|admin->customer`,
      ]);
      const unauth = bad.report?.findings.find((f) => f.ruleId === 'authz.unauthenticated-access');
      // The answer carries the e-mail of the original user (18-D-03).
      expect(unauth?.confidence).toBe('high');
      expect(unauth?.evidence[0]?.kind).toBe('replay');
      expect(bad.outcome?.code).toBe(1);
      expect(bad.report?.authz?.matrix.some((m) => m.result === 'bypassed')).toBe(true);
      expect(bad.output).toMatch(/│ Authz\s+│ enabled · 2 roles \+ anonymous · budget 500/);

      const secure = await shop([]);
      const good = await run(secure);
      passed(good);
      expect(authzFindings(good), good.output).toEqual([]);
      expect(good.outcome?.code, good.output).toBe(0);
      const matrix = good.report?.authz?.matrix ?? [];
      expect(matrix.filter((m) => m.result === 'enforced').length).toBeGreaterThanOrEqual(4);
      expect(good.report?.authz?.replays).toBeGreaterThan(0);
    },
    RUN_TIMEOUT,
  );

  test(
    '18-AC-02 18-AC-04 a public endpoint is not tested and no request leaves the allowed origins',
    async () => {
      const s = await shop(AUTHZ_SWITCHES);
      const r = await run(s);
      passed(r);
      const products = 'GET /api/products/:id';
      expect(authzFindings(r).filter((f) => f.includes('/api/products/'))).toEqual([]);
      expect(
        r.report?.authz?.matrix
          .filter((m) => m.endpointKey === products)
          .every((m) => m.result === 'public'),
      ).toBe(true);
      expect(r.report?.coverage.authzObserved?.[products]?.public).toBe(true);
      // The partner origin is in the scan scope but not allowed: no request of the package.
      expect(s.probes.partner).toBe(0);
      // Every request of the package to the app carries the probe header.
      expect(s.probes.app).toBe(r.report?.authz?.budget.used);
      expect(s.probes.app).toBeGreaterThan(0);
    },
    RUN_TIMEOUT,
  );

  test(
    '18-AC-05 the budget stops the replays',
    async () => {
      const s = await shop([]);
      const r = await run(s, { env: { AUTHZ_MAX_REQUESTS: '3' } });
      passed(r);
      expect(s.probes.app).toBeLessThanOrEqual(3);
      expect(r.report?.authz?.budget).toEqual({ maxRequests: 3, used: 3, exceeded: true });
      expect(r.report?.authz?.skipped.budget).toBeGreaterThan(0);
      expect(r.report?.diagnostics.map((d) => d.code)).toContain('AUTHZ_BUDGET_EXCEEDED');
    },
    RUN_TIMEOUT,
  );

  test(
    '18-AC-06 without authz.enabled or with PW_SEC_AUTHZ=0 the package sends nothing',
    async () => {
      const s = await shop(AUTHZ_SWITCHES);
      const off = await run(s, { env: { AUTHZ: '' } });
      passed(off);
      expect(off.report?.authz).toBeNull();
      expect(off.output).not.toMatch(/│ Authz/);
      const byEnv = await run(s, { env: { PW_SEC_AUTHZ: '0' } });
      passed(byEnv);
      expect(byEnv.report?.authz).toBeNull();
      expect(byEnv.output).toMatch(/│ Authz\s+│ disabled by PW_SEC_AUTHZ=0/);
      expect(s.probes).toEqual({ app: 0, partner: 0 });
      // No templates are made either (05-REQ-28).
      const templates = [...off.output.matchAll(/pw-sec-templates/g)];
      expect(templates).toEqual([]);
      const raw = readFileSync(join(byEnv.dir, 'results.json'), 'utf8');
      expect(raw.includes('pw-sec-templates')).toBe(false);
    },
    RUN_TIMEOUT,
  );

  test(
    '18-AC-07 templates and output files hold no secret and no session value',
    async () => {
      const s = await shop(AUTHZ_SWITCHES);
      const r = await run(s);
      passed(r);
      const raw = readFileSync(join(r.dir, 'results.json'), 'utf8');
      expect(raw.includes('pw-sec-templates')).toBe(true);
      const attachments = [...raw.matchAll(/"name":\s*"pw-sec-templates"[^}]*"body":\s*"([^"]+)"/g)]
        .map((m) => Buffer.from(m[1] ?? '', 'base64').toString('utf8'))
        .join('\n');
      expect(attachments).toContain('"templates"');
      const secrets = [
        ...Object.values(SECRETS),
        ...Object.values(AUTHZ_USERS).flatMap((u) => [u.session, u.email]),
      ];
      const texts = [
        attachments,
        raw,
        ...filesUnder(join(r.dir, 'reports')).map((f) => readFileSync(f, 'utf8')),
        ...filesUnder(join(r.dir, 'test-results')).map((f) => readFileSync(f, 'utf8')),
      ];
      for (const secret of secrets) {
        for (const text of texts) expect(text.includes(secret), secret).toBe(false);
      }
    },
    RUN_TIMEOUT,
  );

  test(
    '18-AC-08 a fixed IDOR resolves its baseline entry; PW_SEC_AUTHZ=0 leaves it not covered',
    async () => {
      const dir = harness.copy('authz');
      const vulnerable = await shop(['authz.horizontal']);
      const baseline = await run(vulnerable, { dir, env: { PW_SEC_MODE: 'baseline' } });
      passed(baseline);
      const entry = Object.keys(
        (JSON.parse(baseline.baseline ?? '{}') as { findings: Record<string, unknown> }).findings,
      ).find((f) => f.startsWith('authz.horizontal|'));
      expect(entry, baseline.output).toBeDefined();

      const fixed = await shop([]);
      const resolved = await run(fixed, { dir });
      expect(resolved.report?.resolved.map((r) => r.fingerprint)).toContain(entry);

      const off = await run(fixed, { dir, env: { PW_SEC_AUTHZ: '0' } });
      expect(off.report?.notCovered.map((r) => r.fingerprint)).toContain(entry);
      expect(off.report?.resolved.map((r) => r.fingerprint)).not.toContain(entry);
    },
    RUN_TIMEOUT,
  );

  test(
    '18-REQ-20 shards replay their own templates and the merge finds the same three bugs',
    async () => {
      const s = await shop(AUTHZ_SWITCHES);
      const single = await run(s);
      const files: Record<string, string> = {};
      for (const shard of ['1/2', '2/2']) {
        const part = await run(s, { args: [`--shard=${shard}`] });
        expect(part.outcome?.name, part.output).toBe('SHARD_WRITTEN');
        const name = `shard-${shard.replace('/', '-of-')}.json`;
        files[name] = readFileSync(join(part.dir, 'reports/pw-sec', name), 'utf8');
        expect(files[name]).toContain('"results"');
      }
      const merged = await merge(harness.copy('authz'), files);
      expect(
        (merged.findings ?? [])
          .filter((f) => f.ruleId.startsWith('authz.'))
          .map((f) => f.fingerprint)
          .sort(),
      ).toEqual(authzFindings(single));
      expect(merged.authz?.matrix.length).toBeGreaterThan(0);
    },
    RUN_TIMEOUT,
  );
});
