import { expect, test } from '../fixtures';

test('page with a script and an API call', async ({ page }) => {
  await page.goto('/page');
  await page.waitForLoadState('networkidle');
});

test('token in localStorage', async ({ page }) => {
  await page.goto('/storage');
  expect(await page.evaluate(() => localStorage.getItem('auth_token'))).toContain('eyJ');
});

test('CSP violation', async ({ page }) => {
  await page.goto('/csp');
  await page.waitForLoadState('networkidle');
});

test('mocked responses are skipped', async ({ page }) => {
  await page.route('**/api/items/*', (route) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: '{"mocked":true}' }),
  );
  await page.goto('/page');
  await page.waitForLoadState('networkidle');
});

test('context closed while a body is read', async ({ browser, security }) => {
  const context = await browser.newContext({ baseURL: process.env.BASE_URL });
  await security.track(context);
  const page = await context.newPage();
  await page.goto('/page');
  const response = page.waitForResponse('**/slow');
  // fetch() resolves with the headers while the body still streams for 3 s; awaiting it (not a
  // floating evaluate) keeps the close from rejecting the evaluate on WebKit.
  await page.evaluate(async () => {
    await fetch('/slow');
  });
  await response;
  await context.close();
});

test('no-store response without requestfinished', async ({ page }) => {
  await page.goto('/page');
  // The page starts the fetch but never reads the body. On Chromium no-store means no
  // requestfinished, so the collector builds a header-only record at the end of the test
  // (05-REQ-29); waiting for the response event keeps the request in scope without reading it.
  const response = page.waitForResponse('**/nostore');
  await page.evaluate(() => {
    void fetch('/nostore');
  });
  await response;
});

test('listeners and bindings only in scan mode', async ({ page, context }) => {
  await page.goto('/page');
  const scanning = (process.env.PW_SEC_MODE ?? '') !== '';
  const listeners = (context as unknown as { listenerCount(e: string): number }).listenerCount(
    'requestfinished',
  );
  const bindings = await page.evaluate(
    () => Object.keys(window).filter((k) => k.startsWith('__pwSec_')).length,
  );
  expect(listeners > 0).toBe(scanning);
  expect(bindings > 0).toBe(scanning);
});

test('worker-scoped context registered with trackContext()', async ({ workerContext }) => {
  const page = await workerContext.newPage();
  await page.goto('/storage');
});
