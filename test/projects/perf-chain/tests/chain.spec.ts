import { expect, test } from '../fixtures';

test('API calls', async ({ request }) => {
  expect((await request.get('/api/items/1')).ok()).toBe(true);
  expect((await request.post('/api/orders', { data: { a: 1 } })).status()).toBe(201);
  expect((await request.fetch('/api/config')).ok()).toBe(true);
});

test('UI page', async ({ page }) => {
  await page.goto('/page');
  await page.waitForLoadState('networkidle');
});
