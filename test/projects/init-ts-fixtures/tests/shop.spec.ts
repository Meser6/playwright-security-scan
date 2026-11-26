import { expect, test } from './fixtures';

test('home', async ({ page, request }) => {
  await page.goto('/');
  await request.get('https://api.example.test/v1/me');
  await page.goto('https://www.googletagmanager.com/gtm.js');
  expect(true).toBe(true);
});
