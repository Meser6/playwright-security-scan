import { expect, test } from '../fixtures';

test('customer opens an own invoice and a product', async ({ page }) => {
  await page.goto('/');
  const invoice = await page.evaluate(() => fetch('/api/invoices/101').then((r) => r.json()));
  expect(invoice.id).toBe(101);
  const product = await page.evaluate(() => fetch('/api/products/1').then((r) => r.json()));
  expect(product.name).toBe('Teapot');
});

test('customer lists the own orders over the API', async ({ request }) => {
  const response = await request.get('/api/me/orders');
  expect(response.status()).toBe(200);
  expect((await response.json()).orders).toHaveLength(1);
  // Another origin in the scan scope, not in authz.allowedOrigins (18-AC-04).
  const partner = process.env.PARTNER_URL;
  if (partner !== undefined) {
    const data = await request.get(`${partner}/api/partner-data`);
    expect((await data.json()).partner).toBe(true);
  }
});
