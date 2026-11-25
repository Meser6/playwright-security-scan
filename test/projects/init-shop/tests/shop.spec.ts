import { expect, test } from './fixtures';

test('home page', async ({ page }) => {
  await page.goto('/');
  await expect(page.locator('h1')).toHaveText('Shop');
});

test('API login', async ({ request }) => {
  expect((await request.post('/api/login')).ok()).toBe(true);
});
