import { expect, test } from 'playwright-security-scan/test';

test('home page', async ({ page }) => {
  await page.goto('/');
  await expect(page.locator('h1')).toHaveText('Shop');
});

test('API login', async ({ request }) => {
  expect((await request.post('/api/login')).ok()).toBe(true);
});

test('security fixture is there', ({ security }) => {
  expect(typeof security.track).toBe('function');
});
