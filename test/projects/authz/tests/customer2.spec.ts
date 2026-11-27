import { expect, test } from '../fixtures';

test('second customer opens an own invoice', async ({ page }) => {
  await page.goto('/');
  const invoice = await page.evaluate(() => fetch('/api/invoices/202').then((r) => r.json()));
  expect(invoice.id).toBe(202);
});
