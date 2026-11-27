// The ZAP driver (19, chapter 5) with a fake Docker and a fake ZAP API: the calls, the budget,
// the hard origin check and the cleanup on every path.
import { describe, expect, test } from 'vitest';
import {
  dockerRunArgs,
  excludeRegexes,
  includeRegexes,
  rawRequest,
  roleHeaders,
  runAttack,
} from '../../../src/active/zap.ts';
import type { AttackOptions, ExecResult, SignalSource } from '../../../src/active/zap.ts';
import { resolveAttack } from '../../../src/core/attack/config.ts';
import type { AttackTemplate } from '../../../src/core/attack/types.ts';
import type { Diagnostic } from '../../../src/core/types/index.ts';

const APP = 'https://localhost:4430';
const SESSION = 'B0bS3ss10nV4lue5Kd9WmQr';

const template = (path: string, extra: Partial<AttackTemplate> = {}): AttackTemplate => ({
  method: 'GET',
  url: `${APP}${path}`,
  headers: [{ name: 'accept', value: 'text/html' }],
  endpointKey: `GET ${path.split('?')[0] ?? ''}${path.includes('?') ? '?q' : ''}`,
  origin: APP,
  project: 'customer',
  source: 'browser',
  context: { testId: 't1', titlePath: ['t'], file: 'a.spec.ts', line: 1, project: 'customer' },
  ...extra,
});

interface Fake {
  calls: { path: string; params: Record<string, string>; key: string | null }[];
  exec: { args: readonly string[] }[];
  diagnostics: Diagnostic[];
  options: AttackOptions;
}

function fake(
  o: {
    docker?: boolean;
    status?: number[];
    messages?: number;
    failOn?: string;
    attack?: Parameters<typeof resolveAttack>[0];
    templates?: AttackTemplate[];
    signals?: SignalSource;
    onPoll?: () => void;
  } = {},
): Fake {
  const f: Fake = {
    calls: [],
    exec: [],
    diagnostics: [],
    options: undefined as never,
  };
  const statuses = [...(o.status ?? [50, 100])];
  const fetchFn = (async (input: string | URL | Request, init?: RequestInit) => {
    const path = String(input)
      .replace(/^http:\/\/127\.0\.0\.1:\d+\/JSON\//, '')
      .replace(/\/$/, '');
    const params = Object.fromEntries(new URLSearchParams(String(init?.body ?? '')));
    const key = new Headers(init?.headers).get('x-zap-api-key');
    f.calls.push({ path, params, key });
    const json = (v: unknown, status = 200): Response =>
      new Response(JSON.stringify(v), { status, headers: { 'content-type': 'application/json' } });
    if (o.failOn === path) return json({ code: 'internal_error' }, 500);
    switch (path) {
      case 'core/view/version':
        return json({ version: '2.17.0' });
      case 'context/action/newContext':
        return json({ contextId: '1' });
      case 'ascan/action/scan':
        return json({ scan: '0' });
      case 'ascan/view/status':
        o.onPoll?.();
        return json({ status: String(statuses.shift() ?? 100) });
      case 'ascan/view/messagesIds':
        return json({ messagesIds: Array.from({ length: o.messages ?? 10 }, (_, i) => String(i)) });
      case 'ascan/view/alertsIds':
        return json({ alertsIds: ['5'] });
      case 'alert/view/alert':
        return json({
          alert: {
            pluginId: '40012',
            name: 'Cross Site Scripting (Reflected)',
            risk: 'High',
            confidence: 'Medium',
            method: 'GET',
            url: `${APP}/search?q=%3Cscript%3E`,
            param: 'q',
            attack: '<script>',
            evidence: '<script>',
            cweid: '79',
            tags: {},
          },
        });
      case 'core/view/numberOfAlerts':
        return json({ numberOfAlerts: '3' });
      default:
        return json({ Result: 'OK' });
    }
  }) as typeof fetch;
  f.options = {
    attack: resolveAttack({ allowedOrigins: [APP], ...o.attack }),
    templates: o.templates ?? [template('/search?q=tea'), template('/api/items?id=1')],
    runId: 'run1',
    role: {
      name: 'customer',
      cookies: [{ name: 'sid', value: SESSION, domain: 'localhost' }],
      headers: {},
    },
    keyOf: (method, url) => {
      const u = new URL(url);
      return { origin: u.origin, key: `${method} ${u.pathname}${u.search === '' ? '' : '?q'}` };
    },
    redact: (t) => t,
    diagnostic: (d) => f.diagnostics.push(d),
    progress: () => undefined,
    platform: 'linux',
    exec: async (_cmd, args): Promise<ExecResult> => {
      f.exec.push({ args });
      if (args[0] === 'version' && o.docker === false) return { code: 1, stdout: '', stderr: 'no' };
      return { code: 0, stdout: '', stderr: '' };
    },
    fetch: fetchFn,
    sleep: async () => undefined,
    port: async () => 41234,
    signals: o.signals ?? { on: () => undefined, off: () => undefined },
    stopSync: (name) => f.exec.push({ args: ['stop-sync', name] }),
  };
  return f;
}

const codes = (f: Fake): string[] => f.diagnostics.map((d) => d.code);
const stops = (f: Fake): string[][] =>
  f.exec.filter((e) => e.args[0] === 'stop' || e.args[0] === 'stop-sync').map((e) => [...e.args]);

describe('the ZAP driver (19, chapter 5)', () => {
  test('19-AC-02 without Docker: ATTACK_DOCKER_MISSING with instructions, nothing started', async () => {
    const f = fake({ docker: false });
    const out = await runAttack(f.options);
    expect(codes(f)).toEqual(['ATTACK_DOCKER_MISSING']);
    expect(f.diagnostics[0]?.level).toBe('error');
    expect(f.diagnostics[0]?.message).toContain('install Docker or set attack.zapUrl');
    expect(f.exec.map((e) => e.args[0])).toEqual(['version']);
    expect(out.summary.completed).toBe(false);
  });

  test('a scan: container, context, credentials, templates, scan, alerts and the stop', async () => {
    const f = fake();
    const out = await runAttack(f.options);
    expect(codes(f)).toEqual([]);
    const run = f.exec.find((e) => e.args[0] === 'run')?.args ?? [];
    expect(run).toEqual(
      expect.arrayContaining(['--network', 'host', 'zaproxy/zap-stable', '-silent', '41234']),
    );
    expect(run).toContain('--name');
    expect(run[run.indexOf('--name') + 1]).toBe('pw-sec-zap-run1');
    // Every API call has the key of the run in the header, never in the URL.
    const key = f.calls[0]?.key;
    expect(key).toMatch(/^[0-9a-f]{32}$/);
    expect(f.calls.every((c) => c.key === key)).toBe(true);
    const replacer = f.calls
      .filter((c) => c.path === 'replacer/action/addRule')
      .map((c) => c.params);
    expect(replacer.map((r) => [r.matchString, r.replacement])).toEqual([
      ['Cookie', `sid=${SESSION}`],
      ['x-pw-sec-probe', 'run1'],
    ]);
    const sent = f.calls.filter((c) => c.path === 'core/action/sendRequest');
    expect(sent.map((c) => c.params.request?.split('\r\n')[0])).toEqual([
      `GET ${APP}/search?q=tea HTTP/1.1`,
      `GET ${APP}/api/items?id=1 HTTP/1.1`,
    ]);
    expect(sent[0]?.params.followRedirects).toBe('false');
    const scan = f.calls.find((c) => c.path === 'ascan/action/scan')?.params;
    expect(scan).toMatchObject({ contextId: '1', inScopeOnly: 'true', recurse: 'true' });
    expect(f.calls.find((c) => c.path === 'ascan/action/disableScanners')?.params).toEqual({
      ids: '40026',
      scanPolicyName: 'pw-sec-run1',
    });
    expect(f.calls.find((c) => c.path === 'ascan/action/setOptionDelayInMs')?.params.Integer).toBe(
      '100',
    );
    expect(out.summary).toMatchObject({
      zapVersion: '2.17.0',
      role: 'customer',
      completed: true,
      requests: 12,
      templates: { sent: 2, failed: 0 },
      alerts: { mapped: 1, falsePositive: 0, passive: 2, off: 0 },
    });
    expect(out.findings.map((x) => x.fingerprint)).toEqual(['zap.40012|endpoint|GET /search?q|q']);
    expect(out.coveredKeys).toEqual(['GET /api/items?q', 'GET /search?q']);
    // 19-AC-04: stopped after the scan.
    expect(stops(f)).toEqual([['stop', 'pw-sec-zap-run1']]);
    expect(JSON.stringify(f.diagnostics)).not.toContain(SESSION);
  });

  test('19-AC-04 the container is stopped after an API error', async () => {
    const f = fake({ failOn: 'ascan/action/scan' });
    const out = await runAttack(f.options);
    expect(codes(f)).toEqual(['ATTACK_ZAP_API_ERROR']);
    expect(f.diagnostics[0]?.message).toContain('ascan/action/scan failed with HTTP 500');
    expect(f.diagnostics[0]?.message).not.toContain(f.calls[0]?.key ?? 'none');
    expect(out.summary.completed).toBe(false);
    expect(stops(f)).toEqual([['stop', 'pw-sec-zap-run1']]);
  });

  test('19-AC-04 Ctrl+C during the scan stops the container at once', async () => {
    let signal: (() => void) | undefined;
    const f = fake({
      status: [10, 20, 30, 100],
      signals: { on: (s) => (signal = s), off: () => undefined },
      onPoll: () => signal?.(),
    });
    const out = await runAttack(f.options);
    expect(stops(f)).toEqual([['stop-sync', 'pw-sec-zap-run1']]);
    expect(codes(f)).toContain('ATTACK_INTERRUPTED');
    expect(out.summary.completed).toBe(false);
  });

  test('14-REQ-04 the budget stops the scan with ATTACK_BUDGET_EXCEEDED', async () => {
    const f = fake({ status: [10, 20, 100], messages: 50, attack: { maxRequests: 20 } });
    const out = await runAttack(f.options);
    expect(codes(f)).toEqual(['ATTACK_BUDGET_EXCEEDED']);
    expect(f.calls.some((c) => c.path === 'ascan/action/stop')).toBe(true);
    expect(out.summary).toMatchObject({ budgetExceeded: true, completed: false });
  });

  test('18-REQ-04 a template of another origin is never given to ZAP', async () => {
    const f = fake({
      templates: [
        template('/search?q=tea', {
          url: 'https://127.0.0.1:4431/x',
          origin: 'https://127.0.0.1:4431',
        }),
        template('/search?q=tea'),
      ],
    });
    await runAttack(f.options);
    expect(codes(f)).toEqual(['ATTACK_ORIGIN_BLOCKED']);
    const sent = f.calls.filter((c) => c.path === 'core/action/sendRequest');
    expect(sent).toHaveLength(1);
    expect(sent[0]?.params.request).not.toContain('127.0.0.1:4431');
  });

  test('without templates the container is not started (ATTACK_NO_TEMPLATES)', async () => {
    const f = fake({ templates: [] });
    await runAttack(f.options);
    expect(codes(f)).toEqual(['ATTACK_NO_TEMPLATES']);
    expect(f.exec.map((e) => e.args[0])).toEqual(['version']);
  });

  test('attack.zapUrl: no Docker, PW_SEC_ZAP_API_KEY, and what the run added is removed', async () => {
    const f = fake({ attack: { zapUrl: 'http://127.0.0.1:8090' } });
    f.options.zapApiKey = 'known-key';
    const calls: string[] = [];
    const inner = f.options.fetch as typeof fetch;
    f.options.fetch = ((input: string | URL | Request, init?: RequestInit) => {
      calls.push(String(input));
      expect(new Headers(init?.headers).get('x-zap-api-key')).toBe('known-key');
      return inner(input, init);
    }) as typeof fetch;
    const out = await runAttack(f.options);
    expect(f.exec).toEqual([]);
    expect(out.summary.zap).toBe('url');
    expect(calls.every((c) => c.startsWith('http://127.0.0.1:8090/JSON/'))).toBe(true);
    const tail = calls.slice(-4).map((c) => c.replace('http://127.0.0.1:8090/JSON/', ''));
    expect(tail).toEqual([
      'context/action/removeContext/',
      'replacer/action/removeRule/',
      'replacer/action/removeRule/',
      'ascan/action/removeScanPolicy/',
    ]);
  });
});

describe('ZAP commands and requests (19 chapter 11a)', () => {
  test('docker run outside Linux maps the same port on the loopback only', () => {
    const args = dockerRunArgs({
      name: 'pw-sec-zap-x',
      image: 'zaproxy/zap-stable',
      port: 5000,
      key: 'k',
      platform: 'darwin',
    });
    expect(args).toEqual(expect.arrayContaining(['-p', '127.0.0.1:5000:5000', '-port', '5000']));
    expect(args).not.toContain('host');
  });

  test('raw request, context patterns and role headers', () => {
    expect(
      rawRequest(
        template('/api/items', {
          method: 'POST',
          headers: [{ name: 'content-type', value: 'application/json' }],
          body: '{"a":1}',
        }),
      ),
    ).toBe(
      `POST ${APP}/api/items HTTP/1.1\r\nHost: localhost:4430\r\ncontent-type: application/json\r\nContent-Length: 7\r\n\r\n{"a":1}`,
    );
    const [include] = includeRegexes([APP]);
    expect(new RegExp(include ?? '').test(`${APP}/search?q=1`)).toBe(true);
    expect(new RegExp(include ?? '').test(`${APP}.evil.test/`)).toBe(false);
    const exclude = excludeRegexes([APP], ['POST /api/orders/*']);
    expect(exclude[1]).toBe('^https://localhost:4430/api/orders/[^/?#]*(?:[?#].*)?$');
    expect(exclude[0]?.startsWith('(?i)')).toBe(true);
    expect(
      roleHeaders(
        {
          name: 'customer',
          cookies: [
            { name: 'sid', value: 'v', domain: 'localhost' },
            { name: 'other', value: 'w', domain: 'partner.test' },
          ],
          headers: { authorization: 'Bearer x' },
        },
        [APP],
      ),
    ).toEqual({ authorization: 'Bearer x', Cookie: 'sid=v' });
  });
});
