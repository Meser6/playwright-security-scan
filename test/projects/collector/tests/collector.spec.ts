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
  void page.evaluate(() => fetch('/slow').catch(() => undefined));
  await response;
  await context.close();
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
