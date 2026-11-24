// V-06: a security-like wrapper of the request fixture layered with the perf package in both
// orders. Run with PW_PERF_MODE=test; perf samples are counted from the JSON report.
import { appendFileSync, mkdirSync } from 'node:fs';
import { test as base, expect } from '@playwright/test';
import type { APIRequestContext } from '@playwright/test';
// @ts-expect-error plain ESM helper without types
import { start } from './server.mjs';
// @ts-expect-error built JS of the read-only sibling package
import { withPerfFixtures } from '../../playwright-performance-regression/dist/fixture.js';

const results = new URL('./results/', import.meta.url);
mkdirSync(results, { recursive: true });

const seen: string[] = [];
const wrapped = new WeakSet<object>();
let depth = 0;
function wrapLikeSecurity(ctx: APIRequestContext): void {
  if (wrapped.has(ctx)) return;
  wrapped.add(ctx);
  const target = ctx as unknown as Record<string, (...args: unknown[]) => unknown>;
  for (const name of ['fetch', 'get', 'post', 'put', 'patch', 'delete', 'head']) {
    const original = target[name]!;
    Object.defineProperty(target, name, {
      configurable: true,
      writable: true,
      value: function (this: unknown, ...args: unknown[]) {
        if (depth > 0) return original.apply(this, args);
        depth += 1;
        try {
          seen.push(`${name} ${String(args[0])}`);
          return original.apply(this, args);
        } finally {
          depth -= 1;
        }
      },
    });
  }
}

const securityFixtures = {
  request: async (
    { request }: { request: APIRequestContext },
    use: (r: APIRequestContext) => Promise<void>,
  ) => {
    wrapLikeSecurity(request);
    await use(request);
  },
};

const withServer = base.extend<object, { server: { http: string; close(): Promise<unknown> } }>({
  server: [
    // eslint-disable-next-line no-empty-pattern
    async ({}, use) => {
      const s = await start();
      await use(s);
      await s.close();
    },
    { scope: 'worker' },
  ],
});

const securityThenPerf = withPerfFixtures(withServer.extend(securityFixtures));
const perfThenSecurity = withPerfFixtures(withServer).extend(securityFixtures);

for (const [order, t] of [
  ['security-inner', securityThenPerf],
  ['perf-inner', perfThenSecurity],
] as const) {
  t(`V-06 ${order}`, async ({ request, server, browserName }) => {
    seen.length = 0;
    const r1 = await request.get(`${server.http}/api`);
    const r2 = await request.fetch(`${server.http}/data.json`);
    const r3 = await request.post(`${server.http}/api`, { data: { a: 1 } });
    expect(r1.status()).toBe(200);
    expect(await r2.json()).toEqual({ items: [1, 2, 3], token: 'secret' });
    expect(r3.status()).toBe(200);
    appendFileSync(
      new URL(`${browserName}-perf.jsonl`, results),
      JSON.stringify({ check: `V-06 ${order}`, data: { securitySaw: [...seen] } }) + '\n',
    );
    expect(seen).toHaveLength(3);
  });
}
