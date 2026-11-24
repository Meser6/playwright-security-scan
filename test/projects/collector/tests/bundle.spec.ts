import { test } from '../fixtures';

for (let i = 0; i < 100; i++) {
  test(`bundle ${i}`, async ({ page }) => {
    await page.goto('/bundle', { waitUntil: 'load' });
  });
}
