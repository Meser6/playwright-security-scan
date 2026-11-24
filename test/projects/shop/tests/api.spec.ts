import { expect, test } from '../fixtures';

test('API login and profile', async ({ request }) => {
  expect((await request.post('/api/login')).ok()).toBe(true);
  expect((await request.get('/api/me')).ok()).toBe(true);
});

test('API token', async ({ request }) => {
  expect((await request.get('/api/token')).ok()).toBe(true);
});

test('API product', async ({ request }) => {
  const response = await request.get('/api/products/42');
  expect(await response.text()).toContain('Teapot');
});

test('API CORS from the partner origin', async ({ request }) => {
  const response = await request.get('/api/cors', {
    headers: { origin: process.env.PARTNER_URL ?? '' },
  });
  expect(response.ok()).toBe(true);
});

test('API error', async ({ request }) => {
  expect((await request.get('/api/fail')).status()).toBeGreaterThanOrEqual(400);
});
