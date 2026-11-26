import { test } from '@playwright/test';

test('b', async ({ request }) => {
  await request.get('/api/health');
});
