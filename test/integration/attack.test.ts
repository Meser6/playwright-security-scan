// The attack mode with ZAP (19, chapter 11a) on the reference app only. Without Docker: the errors
// before the tests, a missing Docker and the baseline that keeps zap.* entries. With ZAP_TEST=1
// (the CI job "Attack (zap)", Linux with Docker): the active scan of the deliberate bugs.
// ZAP_APP_HOST=host.docker.internal runs the ZAP tests on macOS: the app stays on this machine.
import { execFileSync, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { dirname, join } from 'node:path';
import { afterAll, beforeAll, describe, expect, test } from 'vitest';
import { ATTACK_SWITCHES, AUTHZ_USERS, startShop } from '../app/shop.ts';
import type { Shop } from '../app/shop.ts';
import { filesUnder, RUN_TIMEOUT, startHarness } from './harness.ts';
import type { Harness, ProjectRun } from './harness.ts';

const ZAP = process.env.ZAP_TEST === '1';
const ZAP_TIMEOUT = 20 * 60_000;
/** The host ZAP reaches the local app by: localhost on Linux (--network host). */
const APP_HOST = process.env.ZAP_APP_HOST ?? 'localhost';

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

const appUrl = (s: Shop): string => s.url.replace('//localhost:', `//${APP_HOST}:`);

function run(
  s: Shop,
  mode: string,
  options: { env?: Record<string, string>; args?: string[]; dir?: string } = {},
): Promise<ProjectRun> {
  return harness.run(options.dir ?? harness.copy('attack'), {
    env: {
      PW_SEC_MODE: mode,
      ATTACK: '1',
      APP_URL: appUrl(s),
      PARTNER_URL: s.partnerUrl,
      ...options.env,
    },
    ...(options.args === undefined ? {} : { args: options.args }),
  });
}

const zapFindings = (r: ProjectRun): string[] =>
  (r.report?.findings ?? [])
    .filter((f) => f.ruleId.startsWith('zap.'))
    .map((f) => f.fingerprint)
    .sort();

const passed = (r: ProjectRun): void => {
  expect(
    r.results.filter((t) => t.status !== 'passed').map((t) => t.title),
    r.output,
  ).toEqual([]);
};

const containers = (): string =>
  execFileSync('docker', ['ps', '--filter', 'name=pw-sec-zap-', '--format', '{{.Names}}'], {
    encoding: 'utf8',
  }).trim();

describe('attack mode without Docker (19)', () => {
  test(
    '04-AC-09 attack without attack.allowedOrigins and with --shard fails before the tests',
    async () => {
      const s = await shop([]);
      const none = await run(s, 'attack', { env: { ATTACK: '0' } });
      expect(none.status).not.toBe(0);
      expect(none.output).toContain('ATTACK_ORIGINS_REQUIRED');
      expect(none.results).toEqual([]);
      const sharded = await run(s, 'attack', { args: ['--shard=1/2'] });
      expect(sharded.output).toContain('ATTACK_SHARDED');
      expect(sharded.results).toEqual([]);
    },
    RUN_TIMEOUT,
  );

  // A ZAP container reaches the localhost of the reference app only on Linux (19-REQ-05).
  test.skipIf(process.platform !== 'linux')(
    '19-AC-02 without Docker the attack fails with instructions, the passive report is written',
    async () => {
      const s = await shop([]);
      const r = await run(s, 'attack', { env: { PATH: dirname(process.execPath) } });
      passed(r);
      expect(r.outcome?.code, r.output).toBe(3);
      expect(r.output).toContain('ATTACK_DOCKER_MISSING');
      // The console wraps long messages; the report has the whole text.
      expect(
        r.report?.diagnostics.find((d) => d.code === 'ATTACK_DOCKER_MISSING')?.message,
      ).toContain('install Docker or set attack.zapUrl');
      expect(r.report?.mode).toBe('attack');
      expect(r.report?.attack?.completed).toBe(false);
      expect(r.report?.coverage.responses).toBeGreaterThan(0);
      expect(s.probes.app).toBe(0);
    },
    RUN_TIMEOUT,
  );

  test(
    '19-AC-05 a baseline run without the attack keeps the zap.* entries',
    async () => {
      const s = await shop([]);
      const dir = harness.copy('attack');
      const print = 'zap.40012|endpoint|GET /attack/search?q|q';
      writeFileSync(
        join(dir, 'security-baseline.json'),
        `${JSON.stringify(
          {
            schemaVersion: 1,
            generatedBy: 'test',
            findings: {
              [print]: {
                ruleId: 'zap.40012',
                subject: 'GET /attack/search?q',
                severity: 'high',
                status: 'accepted',
                note: 'fixed later',
                addedAt: '2026-11-27',
              },
            },
          },
          null,
          2,
        )}\n`,
      );
      const r = await run(s, 'baseline', { dir, env: { ATTACK: '0' } });
      passed(r);
      expect(r.report?.coverage.endpoints['GET /attack/search?q'], r.output).toBeGreaterThan(0);
      expect(r.report?.notCovered.map((e) => e.fingerprint)).toContain(print);
      expect(Object.keys(JSON.parse(r.baseline ?? '{}').findings)).toContain(print);
    },
    RUN_TIMEOUT,
  );
});

describe.skipIf(!ZAP)('attack mode with ZAP (19, job "Attack (zap)")', () => {
  test(
    '19-AC-01 19-AC-03 19-AC-04 the deliberate XSS is found, written by attack-baseline and accepted',
    async () => {
      const s = await shop(ATTACK_SWITCHES);
      const dir = harness.copy('attack');
      const first = await run(s, 'attack', { dir });
      passed(first);
      const xss = zapFindings(first).filter((f) => f.endsWith('|GET /attack/search?q|q'));
      expect(xss.length, first.output).toBeGreaterThan(0);
      expect(first.outcome?.code, first.output).toBe(1);
      expect(first.report?.attack?.completed).toBe(true);
      expect(first.report?.attack?.role).toBe('customer');
      expect(first.output).toMatch(/│ Attack\s+│ ZAP docker zaproxy\/zap-stable/);
      // 19-AC-03: no request of ZAP left the allowed origins.
      expect(s.probes.partner).toBe(0);
      expect(s.probes.app).toBeGreaterThan(0);
      // 19-AC-04: the container is gone after the scan.
      expect(containers()).toBe('');

      const written = await run(s, 'attack-baseline', { dir });
      passed(written);
      expect(written.outcome?.code, written.output).toBe(0);
      const entries = Object.keys(JSON.parse(written.baseline ?? '{}').findings);
      for (const f of xss) expect(entries).toContain(f);

      const again = await run(s, 'attack', { dir });
      passed(again);
      expect(again.outcome?.code, again.output).toBe(0);
      expect(containers()).toBe('');
    },
    ZAP_TIMEOUT,
  );

  test(
    '19-AC-06 the API key of attack.zapUrl and the session of the role are in no output file',
    async () => {
      const s = await shop(ATTACK_SWITCHES);
      const port = await new Promise<number>((resolve) => {
        const server = createServer().listen(0, '127.0.0.1', () => {
          const address = server.address();
          server.close(() => resolve(typeof address === 'object' && address ? address.port : 0));
        });
      });
      const key = randomBytes(16).toString('hex');
      const name = `pw-sec-zap-test-${randomBytes(3).toString('hex')}`;
      const linux = process.platform === 'linux';
      // A ZAP on the loopback of this machine only.
      execFileSync('docker', [
        'run',
        '--rm',
        '-d',
        '--name',
        name,
        ...(linux ? ['--network', 'host'] : ['-p', `127.0.0.1:${port}:${port}`]),
        'zaproxy/zap-stable',
        'zap.sh',
        '-daemon',
        '-silent',
        '-host',
        linux ? '127.0.0.1' : '0.0.0.0',
        '-port',
        String(port),
        '-config',
        `api.key=${key}`,
        '-config',
        'api.addrs.addr.name=.*',
        '-config',
        'api.addrs.addr.regex=true',
      ]);
      try {
        const zapUrl = `http://127.0.0.1:${port}`;
        for (let i = 0; i < 120; i++) {
          const ok = await fetch(`${zapUrl}/JSON/core/view/version/`, {
            headers: { 'X-ZAP-API-Key': key },
          })
            .then((r) => r.ok)
            .catch(() => false);
          if (ok) break;
          await new Promise((r) => setTimeout(r, 1000));
        }
        const dir = harness.copy('attack');
        const r = await run(s, 'attack', {
          dir,
          env: { ZAP_URL: zapUrl, PW_SEC_ZAP_API_KEY: key },
        });
        passed(r);
        expect(r.report?.attack?.zap).toBe('url');
        expect(r.report?.attack?.completed, r.output).toBe(true);
        expect(zapFindings(r).length).toBeGreaterThan(0);
        expect(s.probes.partner).toBe(0);
        const secrets = [key, AUTHZ_USERS.bob.session];
        for (const file of filesUnder(dir).filter(
          (f) => !/[\\/](?:\.auth|node_modules)[\\/]/.test(f),
        )) {
          const text = readFileSync(file, 'latin1');
          for (const secret of secrets) expect(text.includes(secret), file).toBe(false);
        }
        expect(r.output.includes(key)).toBe(false);
      } finally {
        spawnSync('docker', ['stop', name], { stdio: 'ignore' });
      }
    },
    ZAP_TIMEOUT,
  );
});
