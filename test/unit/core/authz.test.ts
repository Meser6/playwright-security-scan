// The authorization tests without a browser (18): config checks, digests, the comparison, the plan,
// the evaluation and the replays with a fake request context.
import { describe, expect, test } from 'vitest';
import { sendReplays } from '../../../src/active/index.ts';
import type { ContextFactory } from '../../../src/active/index.ts';
import { authzHash, templateHeaders } from '../../../src/collector/templates.ts';
import {
  compareReplay,
  deniedReason,
  digestResponse,
  evaluateAuthz,
  excludeMatcher,
  hasObjectId,
  isLogoutPath,
  planReplays,
  productionPattern,
  resolveAuthz,
  rolesOf,
} from '../../../src/core/authz/index.ts';
import type { AuthzRunData, RequestTemplate } from '../../../src/core/authz/index.ts';
import { resolveConfig, validateConfig } from '../../../src/core/config/index.ts';
import type {
  ResolvedSecurityConfig,
  SecurityConfigInput,
} from '../../../src/core/config/index.ts';
import { readAuthzEnv, readMode } from '../../../src/mode/index.ts';

const hash = authzHash('salt-1');
const codes = (input: unknown): string[] => validateConfig(input).map((i) => `${i.code} ${i.path}`);

function config(input: SecurityConfigInput = {}): ResolvedSecurityConfig {
  const r = resolveConfig({
    ...input,
    authz: {
      enabled: true,
      allowedOrigins: ['https://staging.shop.test'],
      roles: { admin: { level: 1 }, customer: { level: 0 }, customer2: { role: 'customer' } },
      ...input.authz,
    },
  });
  if (!r.ok) throw new Error(JSON.stringify(r.issues));
  return r.config;
}

const PROJECTS = [
  { name: 'setup', storageState: undefined, scanned: true },
  { name: 'admin', storageState: '.auth/admin.json', scanned: true },
  { name: 'customer', storageState: '.auth/bob.json', scanned: true },
  { name: 'customer2', storageState: '.auth/carol.json', scanned: true },
  { name: 'guest', storageState: undefined, scanned: true },
];

const json = (value: unknown, path = '/api/x', status = 200) =>
  digestResponse(
    {
      status,
      contentType: 'application/json',
      body: JSON.stringify(value),
      length: 10,
      path,
    },
    hash,
  );

function template(
  project: string,
  endpointKey: string,
  url: string,
  body: unknown = { id: 1 },
  extra: Partial<RequestTemplate> = {},
): RequestTemplate {
  return {
    method: 'GET',
    url,
    headers: [{ name: 'accept', value: 'application/json' }],
    endpointKey,
    origin: 'https://staging.shop.test',
    project,
    source: 'browser',
    withCredentials: true,
    hadAuthorization: false,
    digest: json(body, new URL(url).pathname),
    context: {
      testId: `t-${project}-${endpointKey}`,
      titlePath: ['t'],
      file: `${project}.spec.ts`,
      line: 1,
      project,
    },
    ...extra,
  };
}

describe('authz config (18-REQ-01…05)', () => {
  test('18-AC-03 enabled without allowedOrigins and with a www. origin fails before the tests', () => {
    expect(codes({ authz: { enabled: true } })).toEqual([
      'AUTHZ_ORIGINS_REQUIRED authz.allowedOrigins',
    ]);
    expect(codes({ authz: { enabled: true, allowedOrigins: [] } })).toEqual([
      'AUTHZ_ORIGINS_REQUIRED authz.allowedOrigins',
    ]);
    expect(codes({ authz: { enabled: true, allowedOrigins: ['https://www.shop.com'] } })).toEqual([
      'AUTHZ_ORIGIN_DENIED authz.allowedOrigins[0]',
    ]);
    expect(resolveConfig({ authz: { enabled: true } }).ok).toBe(false);
  });

  test('18-AC-03 denyOrigins wins over iUnderstandThisIsNotProduction', () => {
    expect(
      codes({
        authz: {
          enabled: true,
          allowedOrigins: ['https://shop.com', 'https://staging.shop.com'],
          denyOrigins: ['https://staging.shop.com'],
          iUnderstandThisIsNotProduction: true,
        },
      }),
    ).toEqual(['AUTHZ_ORIGIN_DENIED authz.allowedOrigins[1]']);
  });

  test('allowedOrigins takes exact origins only; disabled tests need no origins', () => {
    expect(codes({ authz: { enabled: true, allowedOrigins: ['https://*.shop.test'] } })).toEqual([
      'CONFIG_INVALID_VALUE authz.allowedOrigins[0]',
    ]);
    expect(codes({ authz: { enabled: false } })).toEqual([]);
    expect(codes({ authz: { maxRps: 0, similarity: 2, roles: { a: { level: -1 } } } })).toEqual([
      'CONFIG_INVALID_TYPE authz.maxRps',
      'CONFIG_INVALID_TYPE authz.similarity',
      'CONFIG_INVALID_TYPE authz.roles.a.level',
    ]);
    expect(
      codes({ rules: { 'authz.horizontal': 'off', 'authz.vertical': { severity: 'medium' } } }),
    ).toEqual([]);
  });

  test('production patterns (18-REQ-03)', () => {
    expect(productionPattern('https://www.shop.com')).toBe('www.*');
    expect(productionPattern('https://api.prod.shop.com')).toBe('*prod*');
    expect(productionPattern('https://shop-production.eu')).toBe('*production*');
    expect(productionPattern('https://practicesoftwaretesting.com')).toBe(
      'domain without a subdomain',
    );
    for (const ok of [
      'https://localhost:8443',
      'http://127.0.0.1:3000',
      'https://app.localhost',
      'https://api.practicesoftwaretesting.com',
      'https://staging.shop.com',
      'https://product.shop.com',
    ])
      expect(productionPattern(ok), ok).toBeNull();
    const authz = resolveAuthz({ iUnderstandThisIsNotProduction: true });
    expect(deniedReason('https://shop.com', authz)).toBeNull();
  });

  test('presets leave the authz tests on; the banner count is without them (18 chapter 12a)', () => {
    const minimal = config({ rules: { preset: 'minimal' } });
    expect(minimal.rules['authz.horizontal']?.enabled).toBe(true);
    expect(
      config({ rules: { 'authz.horizontal': 'off' } }).rules['authz.horizontal']?.enabled,
    ).toBe(false);
  });

  test('PW_SEC_AUTHZ (18-REQ-05) and the hint of PW_SEC_MODE=active', () => {
    expect(readAuthzEnv({})).toEqual({ ok: true, off: false });
    expect(readAuthzEnv({ PW_SEC_AUTHZ: '' })).toEqual({ ok: true, off: false });
    expect(readAuthzEnv({ PW_SEC_AUTHZ: '0' })).toEqual({ ok: true, off: true });
    const bad = readAuthzEnv({ PW_SEC_AUTHZ: '1' });
    expect(bad.ok ? '' : bad.issues[0]?.code).toBe('AUTHZ_ENV_INVALID');
    const active = readMode({ PW_SEC_MODE: 'active' });
    expect(active.ok ? '' : active.issues[0]?.message).toContain('authz.enabled');
  });

  test('exclude patterns and logout paths (18-REQ-10)', () => {
    const excluded = excludeMatcher(['GET */api/shared/*', '/api/health']);
    expect(excluded('GET api.test/api/shared/1')).toBe(true);
    expect(excluded('HEAD api.test/api/shared/1')).toBe(false);
    expect(excluded('GET /api/health')).toBe(true);
    expect(excluded('HEAD /api/health')).toBe(true);
    expect(excluded('GET /api/shared/1/x')).toBe(false);
    expect(isLogoutPath('/auth/Sign-Out')).toBe(true);
    expect(isLogoutPath('/api/logouts')).toBe(false);
  });
});

describe('digests and the comparison (18-REQ-12, 18-REQ-15)', () => {
  test('a digest holds salted 8-character hashes, never a value', () => {
    const d = json({ items: [{ id: 7, email: 'alice@example.com' }] }, '/api/me');
    expect(d.kind).toBe('json');
    expect(d.keyPaths).toHaveLength(3);
    for (const h of [...(d.keyPaths ?? []), ...(d.leaves ?? []), ...d.markers])
      expect(h).toMatch(/^[0-9a-f]{8}$/);
    expect(JSON.stringify(d)).not.toContain('alice');
    // The e-mail of a profile answer is a marker; another salt gives other hashes.
    expect(d.markers).toHaveLength(1);
    const other = digestResponse(
      { status: 200, contentType: 'application/json', body: '{"a":1}', length: 7, path: '/' },
      authzHash('salt-2'),
    );
    expect(other.keyPaths).not.toEqual(json({ a: 1 }).keyPaths);
  });

  test('JWT claims of the original request are markers', () => {
    const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const token = `${b64({ alg: 'HS256' })}.${b64({ sub: 'user-42' })}.c2ln`;
    const d = digestResponse(
      {
        status: 200,
        contentType: 'application/json',
        body: '{"owner":"user-42"}',
        length: 19,
        path: '/api/orders/1',
        requestHeaders: [{ name: 'authorization', value: `Bearer ${token}` }],
      },
      hash,
    );
    expect(d.markers).toEqual([hash('user-42')]);
    const r = compareReplay(
      d,
      {
        status: 200,
        contentType: 'application/json',
        body: '{"owner":"user-42"}',
        length: 19,
        path: '/',
      },
      hash,
      0.8,
    );
    expect(r).toMatchObject({ verdict: 'similar', markers: true, similarity: 1 });
  });

  const original = json({ id: 101, owner: 'bob', lines: [{ sku: 'TEA', qty: 2 }] });
  const replay = (status: number, body: unknown, type = 'application/json') =>
    compareReplay(
      original,
      {
        status,
        contentType: type,
        body: typeof body === 'string' ? body : JSON.stringify(body),
        length: 10,
        path: '/',
      },
      hash,
      0.8,
    );

  test('denials: statuses, empty lists, sign-in pages', () => {
    for (const status of [401, 403, 404, 405, 302, 500, 503])
      expect(replay(status, { id: 101 }).verdict, String(status)).toBe('denied');
    expect(replay(200, []).verdict).toBe('denied');
    expect(replay(200, { items: [], other: [] }).verdict).toBe('denied');
    expect(
      replay(200, '<html><title>Sign in</title><body>x</body></html>', 'text/html').verdict,
    ).toBe('denied');
  });

  test('similar and different answers', () => {
    expect(replay(200, { id: 101, owner: 'bob', lines: [{ sku: 'TEA', qty: 2 }] })).toMatchObject({
      verdict: 'similar',
      similarity: 1,
    });
    // B gets its own invoice under the same URL: other values.
    expect(replay(200, { id: 202, owner: 'carol', lines: [{ sku: 'MUG', qty: 1 }] }).verdict).toBe(
      'different',
    );
    expect(replay(200, '<p>hi</p>', 'text/html').verdict).toBe('different');
    // Without a body only status and length (±10 %).
    const other = digestResponse(
      { status: 200, contentType: 'image/png', body: undefined, length: 100, path: '/' },
      hash,
    );
    const near = compareReplay(
      other,
      { status: 200, contentType: 'image/png', body: undefined, length: 105, path: '/' },
      hash,
      0.8,
    );
    expect(near).toMatchObject({ verdict: 'similar', kind: 'other' });
    const far = compareReplay(
      other,
      { status: 200, contentType: 'image/png', body: undefined, length: 150, path: '/' },
      hash,
      0.8,
    );
    expect(far.verdict).toBe('different');
  });
});

describe('templates (18-REQ-11)', () => {
  test('only allow-listed headers, never a credential', () => {
    expect(
      templateHeaders([
        { name: 'accept', value: 'application/json' },
        { name: 'cookie', value: 'sid=x' },
        { name: 'authorization', value: 'Bearer x' },
        { name: 'x-xsrf-token', value: 'x' },
        { name: 'x-csrf', value: 'abc' },
        { name: 'x-api-key', value: 'k' },
        { name: 'user-agent', value: 'ua' },
      ]).map((h) => h.name),
    ).toEqual(['accept', 'x-csrf']);
  });
});

describe('roles and the plan (18-REQ-07, 18-REQ-14)', () => {
  const sec = config();
  const roles = rolesOf(PROJECTS, sec.authz);
  const T = {
    users: template('admin', 'GET /api/admin/users', 'https://staging.shop.test/api/admin/users'),
    invoice: template(
      'customer',
      'GET /api/invoices/:id',
      'https://staging.shop.test/api/invoices/101',
    ),
    orders: template(
      'customer',
      'GET /api/orders',
      'https://staging.shop.test/api/orders?order=12',
    ),
    product: template(
      'customer',
      'GET /api/products/:id',
      'https://staging.shop.test/api/products/1',
    ),
  };

  test('roles from projects with storageState; customer2 shares the role customer', () => {
    expect(roles.map((r) => [r.name, r.projects, r.level])).toEqual([
      ['admin', ['admin'], 1],
      ['customer', ['customer', 'customer2'], 0],
    ]);
  });

  test('object ids in the key or the query', () => {
    expect(hasObjectId(T.invoice)).toBe(true);
    expect(hasObjectId(T.orders)).toBe(true);
    expect(hasObjectId(T.users)).toBe(false);
  });

  test('unauthenticated, horizontal and vertical replays; public keys and roles that saw the key are left out', () => {
    const plan = planReplays(
      Object.values(T),
      roles,
      {
        'GET /api/products/:id': { roles: ['customer'], public: true },
      },
      sec,
    );
    const rows = plan.replays.map(
      (p) =>
        `${p.test} ${p.template.endpointKey} ${p.fromRole}->${p.asRole}${p.decided === undefined ? '' : ` (${p.decided.result})`}`,
    );
    expect(rows).toEqual([
      'unauthenticated GET /api/admin/users admin->anonymous',
      'unauthenticated GET /api/invoices/:id customer->anonymous',
      'unauthenticated GET /api/orders customer->anonymous',
      'unauthenticated GET /api/products/:id customer->anonymous (public)',
      'horizontal GET /api/invoices/:id customer->customer',
      'horizontal GET /api/orders customer->customer',
      'horizontal GET /api/products/:id customer->customer (public)',
      'vertical GET /api/admin/users admin->customer',
    ]);
    const seen = planReplays(
      [T.users],
      roles,
      { 'GET /api/admin/users': { roles: ['admin', 'customer'], public: false } },
      sec,
    );
    expect(seen.replays.filter((p) => p.test === 'vertical')).toEqual([]);
  });

  test('a test or a rule switched off plans nothing; one user of a role is a note', () => {
    const off = config({
      authz: { tests: { unauthenticated: false } },
      rules: { 'authz.vertical': 'off' },
    });
    expect(
      new Set(planReplays(Object.values(T), roles, {}, off).replays.map((p) => p.test)),
    ).toEqual(new Set(['horizontal']));
    const single = rolesOf(
      PROJECTS.filter((p) => p.name !== 'customer2'),
      sec.authz,
    );
    expect(planReplays([T.invoice], single, {}, sec).notes).toEqual([
      'horizontal: needs two users of one role',
    ]);
  });

  test('a request with Authorization is not replayed as a role without headers.authorization', () => {
    const bearer = { ...T.invoice, hadAuthorization: true };
    const plan = planReplays([bearer], roles, {}, sec);
    expect(plan.replays.find((p) => p.test === 'horizontal')?.decided).toEqual({
      result: 'skipped',
      reason: 'no-credentials',
    });
    expect(plan.replays.find((p) => p.test === 'unauthenticated')?.decided).toBeUndefined();
  });

  test('the first template per key and project wins, in test order', () => {
    const later = {
      ...T.invoice,
      context: { ...T.invoice.context, file: 'z.spec.ts' },
      url: 'https://staging.shop.test/api/invoices/999',
    };
    const plan = planReplays([later, T.invoice], roles, {}, sec);
    expect(plan.templates).toBe(1);
    expect(plan.replays[0]?.template.url).toBe(T.invoice.url);
  });
});

describe('evaluation (18-REQ-16, 18-REQ-17, 18-REQ-20)', () => {
  const sec = config();
  const base = {
    endpointKey: 'GET /api/invoices/:id',
    origin: 'https://staging.shop.test',
    fromProject: 'customer',
    originalStatus: 200,
    kind: 'json' as const,
    markers: false,
    source: 'browser' as const,
    context: { testId: 't1', titlePath: ['t'], file: 'a.spec.ts', line: 3, project: 'customer' },
  };
  const data = (results: AuthzRunData['results']): AuthzRunData => ({
    roles: [{ name: 'customer', projects: ['customer', 'customer2'], level: 0 }],
    templates: 1,
    budget: { maxRequests: 500, used: results.length, exceeded: false },
    results,
    notes: [],
  });

  test('a similar replay is a finding with role names in the fingerprint and no value in the evidence', () => {
    const e = evaluateAuthz(
      data([
        {
          ...base,
          test: 'horizontal',
          fromRole: 'customer',
          asRole: 'customer',
          asProject: 'customer2',
          result: 'similar',
          status: 200,
          similarity: 0.97,
        },
        {
          ...base,
          test: 'unauthenticated',
          fromRole: 'customer',
          asRole: 'anonymous',
          asProject: null,
          result: 'denied',
          status: 401,
        },
      ]),
      {},
      sec,
    );
    expect(e.findings.map((f) => f.fingerprint)).toEqual([
      'authz.horizontal|endpoint|GET /api/invoices/:id|customer->customer',
    ]);
    expect(e.findings[0]?.evidence[0]).toEqual({
      kind: 'replay',
      snippet: 'status 200 → 200, similarity 0.97, replayed as customer2 (role customer)',
    });
    expect(e.findings[0]?.confidence).toBe('medium');
    expect([...e.passed]).toEqual([
      'authz.unauthenticated-access|endpoint|GET /api/invoices/:id|customer->anonymous',
    ]);
    expect(e.summary.matrix.map((m) => m.result)).toEqual(['enforced', 'bypassed']);
    expect(e.summary.replays).toBe(2);
  });

  test('the merge drops public keys and roles that got the key themselves (18-REQ-20)', () => {
    const e = evaluateAuthz(
      data([
        {
          ...base,
          test: 'unauthenticated',
          fromRole: 'customer',
          asRole: 'anonymous',
          asProject: null,
          result: 'similar',
          status: 200,
          similarity: 1,
        },
        {
          ...base,
          endpointKey: 'GET /api/admin',
          test: 'vertical',
          fromRole: 'admin',
          asRole: 'customer',
          asProject: 'customer',
          result: 'similar',
          status: 200,
          similarity: 1,
        },
      ]),
      {
        'GET /api/invoices/:id': { roles: ['customer'], public: true },
        'GET /api/admin': { roles: ['admin', 'customer'], public: false },
      },
      sec,
    );
    expect(e.findings).toEqual([]);
    expect(e.summary.matrix.map((m) => m.result)).toEqual(['public']);
  });

  test('confidence: high with markers, low without a comparable body; severity overrides apply', () => {
    const over = config({ rules: { 'authz.unauthenticated-access': { severity: 'critical' } } });
    const e = evaluateAuthz(
      data([
        {
          ...base,
          test: 'unauthenticated',
          fromRole: 'customer',
          asRole: 'anonymous',
          asProject: null,
          result: 'similar',
          status: 200,
          similarity: 1,
          markers: true,
        },
        {
          ...base,
          endpointKey: 'GET /file',
          test: 'unauthenticated',
          fromRole: 'customer',
          asRole: 'anonymous',
          asProject: null,
          result: 'similar',
          status: 200,
          similarity: 1,
          kind: 'other',
        },
      ]),
      {},
      over,
    );
    expect(e.findings.map((f) => `${f.severity}/${f.confidence}`)).toEqual([
      'critical/high',
      'critical/low',
    ]);
  });
});

describe('replays (18-REQ-04, 18-REQ-14)', () => {
  const sec = config({ authz: { maxRps: 1000 } });
  const roles = rolesOf(PROJECTS, sec.authz);
  const tpl = template(
    'customer',
    'GET /api/invoices/:id',
    'https://staging.shop.test/api/invoices/101',
    { id: 101 },
  );

  function fake(status = 200, body: unknown = { id: 101 }) {
    const sent: {
      url: string;
      headers: Record<string, string>;
      context: Record<string, unknown>;
    }[] = [];
    const factory: ContextFactory = (options) =>
      Promise.resolve({
        fetch: (url: unknown, o?: { headers?: Record<string, string> }) => {
          sent.push({
            url: String(url),
            headers: o?.headers ?? {},
            context: options as unknown as Record<string, unknown>,
          });
          const text = JSON.stringify(body);
          return Promise.resolve({
            status: () => status,
            headers: () => ({ 'content-type': 'application/json' }),
            body: () => Promise.resolve(Buffer.from(text)),
          } as never);
        },
        dispose: () => Promise.resolve(),
      });
    return { factory, sent };
  }

  const options = (
    factory: ContextFactory,
    overrides: Partial<Parameters<typeof sendReplays>[1]> = {},
  ) => ({
    authz: sec.authz,
    roles,
    projects: PROJECTS.map((p) => ({ ...p, ignoreHTTPSErrors: true })),
    runId: 'run-1',
    hash,
    configDir: import.meta.dirname,
    maxBodyBytes: 1_000_000,
    diagnostic: () => undefined,
    newContext: factory,
    ...overrides,
  });

  test('the probe header, no credentials for anonymous, the state of the role for others', async () => {
    const { factory, sent } = fake(401);
    const plan = planReplays(
      [tpl],
      roles.map((r) => ({ ...r, projects: r.projects })),
      {},
      sec,
    );
    const out = await sendReplays(
      { ...plan, replays: plan.replays.filter((p) => p.test === 'unauthenticated') },
      options(factory),
    );
    expect(out.results.map((r) => r.result)).toEqual(['denied']);
    expect(sent[0]?.context).toMatchObject({
      extraHTTPHeaders: { 'x-pw-sec-probe': 'run-1' },
      ignoreHTTPSErrors: true,
    });
    expect(sent[0]?.context.storageState).toBeUndefined();
    expect(sent[0]?.headers).toEqual({ accept: 'application/json' });
  });

  test('a missing storageState file skips the role with AUTHZ_STATE_MISSING', async () => {
    const { factory, sent } = fake();
    const diagnostics: string[] = [];
    const plan = planReplays([tpl], roles, {}, sec);
    const out = await sendReplays(
      { ...plan, replays: plan.replays.filter((p) => p.test === 'horizontal') },
      options(factory, { diagnostic: (d) => diagnostics.push(d.code) }),
    );
    expect(out.results.map((r) => r.reason)).toEqual(['state-missing']);
    expect(diagnostics).toEqual(['AUTHZ_STATE_MISSING']);
    expect(sent).toEqual([]);
  });

  test('18-AC-04 a template outside allowedOrigins is never sent (AUTHZ_ORIGIN_BLOCKED)', async () => {
    const { factory, sent } = fake();
    const diagnostics: string[] = [];
    const outside = { ...tpl, url: 'https://partner.test/api/invoices/101' };
    const plan = planReplays([outside], roles, {}, sec);
    const out = await sendReplays(
      { ...plan, replays: plan.replays.filter((p) => p.test === 'unauthenticated') },
      options(factory, { diagnostic: (d) => diagnostics.push(`${d.code} ${d.level}`) }),
    );
    expect(sent).toEqual([]);
    expect(out.results[0]?.reason).toBe('origin-blocked');
    expect(diagnostics).toEqual(['AUTHZ_ORIGIN_BLOCKED error']);
  });

  test('18-AC-05 the budget: at most maxRequests, then skipped with AUTHZ_BUDGET_EXCEEDED; the rate is kept', async () => {
    const { factory, sent } = fake(401);
    const tight = config({ authz: { maxRequests: 2, maxRps: 2 } });
    const many = [1, 2, 3, 4].map((n) =>
      template('customer', `GET /api/e${n}`, `https://staging.shop.test/api/e${n}`),
    );
    const plan = planReplays(many, roles, {}, tight);
    const waits: number[] = [];
    let clock = 0;
    const diagnostics: string[] = [];
    const out = await sendReplays(
      { ...plan, replays: plan.replays.filter((p) => p.test === 'unauthenticated') },
      options(factory, {
        authz: tight.authz,
        now: () => clock,
        sleep: (ms) => {
          waits.push(ms);
          clock += Math.max(0, ms);
          return Promise.resolve();
        },
        diagnostic: (d) => diagnostics.push(d.code),
      }),
    );
    expect(sent).toHaveLength(2);
    expect(out).toMatchObject({ used: 2, exceeded: true });
    expect(out.results.map((r) => r.reason ?? r.result)).toEqual([
      'denied',
      'denied',
      'budget',
      'budget',
    ]);
    expect(diagnostics).toEqual(['AUTHZ_BUDGET_EXCEEDED']);
    expect(waits[1]).toBe(500);
  });
});
