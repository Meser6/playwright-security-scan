import { request as playwrightRequest } from '@playwright/test';
import { expect, test } from '../fixtures';

const scanning = (process.env.PW_SEC_MODE ?? '') !== '';

test('API GET item', async ({ request }) => {
  const response = await request.get('/api/items/1');
  expect(await response.json()).toEqual({ id: '1', name: 'Item' });
});

test('API POST order', async ({ request }) => {
  const response = await request.post('/api/orders', {
    data: { item: 1 },
    headers: { 'X-Trace': 'abc' },
  });
  expect(response.status()).toBe(201);
});

test('API fetch config with a secret', async ({ request }) => {
  const response = await request.fetch('/api/config', { method: 'get' });
  expect(response.ok()).toBe(true);
});

test('API timeout gives the original error', async ({ request }) => {
  const error = await request.get('/api/hang', { timeout: 300 }).catch((e: unknown) => e);
  expect(error).toBeInstanceOf(Error);
  expect((error as Error).message).toMatch(/Timeout 300ms exceeded/);
  expect((error as Error).name).toBe('TimeoutError');
});

test('request methods are wrapped only in scan mode', async ({ request }) => {
  expect(Object.prototype.hasOwnProperty.call(request, 'get')).toBe(scanning);
  expect(Object.prototype.hasOwnProperty.call(request, 'fetch')).toBe(scanning);
});

test('API origin out of scope', async ({ request }) => {
  const response = await request.get(`${process.env.HTTPS_URL}/api/items/2`, {
    ignoreHTTPSErrors: true,
  });
  expect(response.ok()).toBe(true);
});

test('page.request is scanned', async ({ page }) => {
  const response = await page.request.get('/api/items/3');
  expect(response.ok()).toBe(true);
});

test('trackRequestContext scans a context from playwright.request', async ({ security }) => {
  const context = await playwrightRequest.newContext({ baseURL: process.env.BASE_URL });
  security.trackRequestContext(context);
  await context.get('/api/items/4');
  await context.dispose();
});

test('UI test on the same endpoint', async ({ page }) => {
  await page.goto('/page');
  await page.waitForLoadState('networkidle');
});
