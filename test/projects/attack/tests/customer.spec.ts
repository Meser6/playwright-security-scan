import { expect, test } from '../fixtures';

test('customer searches the shop', async ({ page }) => {
  await page.goto('/attack/search?q=tea');
  await expect(page.locator('h1')).toContainText('Results for tea');
});

test('customer opens an item', async ({ page, request }) => {
  await page.goto('/');
  const item = await page.evaluate(() => fetch('/api/items?id=1').then((r) => r.json()));
  expect(item.name).toBe('Teapot');
  // Another origin in the scan scope, never in attack.allowedOrigins (19-AC-03).
  const partner = process.env.PARTNER_URL;
  if (partner !== undefined) {
    const data = await request.get(`${partner}/api/partner-data`);
    expect((await data.json()).partner).toBe(true);
  }
});
