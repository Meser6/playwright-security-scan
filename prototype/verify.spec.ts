// Prototype checks V-01 … V-07 (WP-02). Each check records what it observed in
// prototype/results/<browser>.jsonl; RESULTS.md summarises them. Not part of the package.
import { appendFileSync, mkdirSync } from 'node:fs';
import { test as base, expect } from '@playwright/test';
import type { Request, Response } from '@playwright/test';
// @ts-expect-error plain ESM helper without types
import { start } from './server.mjs';

const perfMode = process.env.PW_PERF_MODE !== undefined;

interface Server {
  http: string;
  https: string;
}

const results = new URL('./results/', import.meta.url);
mkdirSync(results, { recursive: true });

function record(browser: string, check: string, data: unknown): void {
  appendFileSync(
    new URL(`${browser}${perfMode ? '-perf' : ''}.jsonl`, results),
    JSON.stringify({ check, data }) + '\n',
  );
}

const test = base.extend<object, { server: Server }>({
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

test('V-01 headersArray keeps repeated set-cookie (browser and API)', async ({
  page,
  server,
  browserName,
  request,
}) => {
  const [response] = await Promise.all([
    page.waitForResponse('**/cookies'),
    page.goto(`${server.http}/cookies`),
  ]);
  const browserHeaders = await response.headersArray();
  const browserCookies = browserHeaders
    .filter((h) => h.name.toLowerCase() === 'set-cookie')
    .map((h) => h.value);
  const apiResponse = await request.get(`${server.http}/api`);
  const apiCookies = apiResponse
    .headersArray()
    .filter((h) => h.name.toLowerCase() === 'set-cookie')
    .map((h) => h.value);
  const allHeadersJoined = (await response.allHeaders())['set-cookie'];
  record(browserName, 'V-01', {
    browserCount: browserCookies.length,
    browserCookies,
    apiCount: apiCookies.length,
    headerNames: browserHeaders.map((h) => h.name),
    allHeadersSetCookie: allHeadersJoined,
  });
  expect(browserCookies).toHaveLength(3);
  expect(apiCookies).toHaveLength(2);
});

test('V-02 response.body() at requestfinished for HTML, JSON, JS', async ({
  page,
  server,
  browserName,
}) => {
  const bodies: Record<string, { type: string; bytes: number } | { error: string }> = {};
  const pending: Promise<void>[] = [];
  page.context().on('requestfinished', (request: Request) => {
    pending.push(
      (async () => {
        const response = await request.response();
        const path = new URL(request.url()).pathname;
        try {
          const body = await response!.body();
          bodies[path] = { type: request.resourceType(), bytes: body.length };
        } catch (error) {
          bodies[path] = { error: String(error).slice(0, 200) };
        }
      })(),
    );
  });
  await page.goto(`${server.http}/page`);
  await page.waitForLoadState('networkidle');
  await Promise.all(pending);
  record(browserName, 'V-02', bodies);
  expect(Object.keys(bodies).sort()).toEqual(['/app.js', '/data.json', '/page']);
});

test('V-02b response.body() after the context closed', async ({ browser, server, browserName }) => {
  const context = await browser.newContext();
  const page = await context.newPage();
  let response: Response | null = null;
  // The response event arrives with headers, before the slow body ends.
  const gotResponse = new Promise<void>((resolve) => {
    context.on('response', (r) => {
      if (r.url().endsWith('/slow')) {
        response = r;
        resolve();
      }
    });
  });
  await page.goto(`${server.http}/page`);
  void page.evaluate(() => fetch('/slow').catch(() => undefined));
  await gotResponse;
  const bodyPromise = (response as unknown as Response).body().then(
    (b) => ({ ok: true, bytes: b.length }),
    (e: unknown) => ({ ok: false, error: String(e).slice(0, 200) }),
  );
  await context.close();
  const outcome = await bodyPromise;
  let afterClose: unknown;
  try {
    afterClose = { ok: true, bytes: (await (response as unknown as Response).body()).length };
  } catch (error) {
    afterClose = { ok: false, error: String(error).slice(0, 200) };
  }
  record(browserName, 'V-02b', { duringClose: outcome, afterClose });
  expect((outcome as { ok: boolean }).ok).toBe(false);
});

test('V-03 serverAddr() for route.fulfill() and real responses', async ({
  page,
  server,
  browserName,
}) => {
  await page.route('**/data.json', (route) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: '{"mocked":true}' }),
  );
  const seen: Record<string, unknown> = {};
  const pending: Promise<void>[] = [];
  page.on('response', (r) => {
    pending.push(
      r.serverAddr().then((addr) => {
        seen[new URL(r.url()).pathname] = addr;
      }),
    );
  });
  await page.goto(`${server.http}/page`);
  await page.waitForLoadState('networkidle');
  await Promise.all(pending);
  record(browserName, 'V-03', seen);
  expect(seen['/data.json']).toBeNull();
  expect(seen['/page']).not.toBeNull();
});

const CSP_SCRIPT = (binding: string): string => `(() => {
  if (typeof document === 'undefined') return;
  document.addEventListener('securitypolicyviolation', (e) => {
    try {
      window['${binding}']({
        directive: e.effectiveDirective || e.violatedDirective,
        blocked: e.blockedURI,
        disposition: e.disposition,
        documentURI: e.documentURI,
      });
    } catch {}
  }, true);
})();`;

test('V-04 addInitScript + exposeBinding catch securitypolicyviolation', async ({
  browser,
  server,
  browserName,
}) => {
  const context = await browser.newContext();
  const binding = `__pwSec_${Math.random().toString(36).slice(2, 8)}`;
  const events: unknown[] = [];
  await context.exposeBinding(binding, (_source, event: unknown) => {
    events.push(event);
  });
  await context.addInitScript(CSP_SCRIPT(binding));
  const page = await context.newPage();
  await page.goto(`${server.http}/csp`);
  await page.waitForTimeout(500);
  const inlineRan = await page.evaluate(
    () => (window as unknown as { inlineRan?: boolean }).inlineRan,
  );
  await page.goto(`${server.http}/csp-report-only`);
  await page.waitForTimeout(500);
  record(browserName, 'V-04', { events, inlineRanOnEnforcedPage: inlineRan ?? false });
  await context.close();
  expect(events.length).toBeGreaterThan(0);
});

let teardownObservation: unknown;
const withTeardownScan = test.extend<{ scanContext: void }>({
  scanContext: [
    async ({ context, browserName }, use) => {
      await use();
      // Teardown of a fixture that depends on `context`: runs before the context closes.
      const started = Date.now();
      const pages = context.pages();
      const storage = [];
      for (const page of pages) {
        try {
          storage.push(
            await page.evaluate(() => ({
              origin: location.origin,
              local: Object.keys(localStorage),
              session: Object.keys(sessionStorage),
            })),
          );
        } catch (error) {
          storage.push({ error: String(error).slice(0, 200) });
        }
      }
      const cookies = (await context.cookies()).map((c) => c.name);
      teardownObservation = { pages: pages.length, storage, cookies, ms: Date.now() - started };
      record(browserName, 'V-05', teardownObservation);
    },
    { auto: true },
  ],
});

withTeardownScan('V-05 localStorage readable in the context teardown', async ({ page, server }) => {
  await page.goto(`${server.http}/cookies`);
  await page.goto(`${server.http}/storage`);
  expect(await page.evaluate(() => localStorage.getItem('token'))).toContain('eyJ');
});

test('V-07 securityDetails() on HTTPS with a self-signed certificate', async ({
  browser,
  server,
  browserName,
}) => {
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();
  const response = await page.goto(`${server.https}/page`);
  const details = await response!.securityDetails();
  const apiContext = await (
    await import('@playwright/test')
  ).request.newContext({
    ignoreHTTPSErrors: true,
  });
  const apiResponse = await apiContext.get(`${server.https}/api`);
  const apiHasSecurityDetails =
    typeof (apiResponse as unknown as { securityDetails?: unknown }).securityDetails === 'function';
  record(browserName, 'V-07', { details, apiHasSecurityDetails });
  await apiContext.dispose();
  await context.close();
  expect(details).not.toBeNull();
});
