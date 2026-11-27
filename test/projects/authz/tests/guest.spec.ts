import { expect, test } from '../fixtures';

test('guest sees the shop and a product', async ({ page }) => {
  await page.goto('/');
  const product = await page.evaluate(() => fetch('/api/products/1').then((r) => r.json()));
  expect(product.name).toBe('Teapot');
});
