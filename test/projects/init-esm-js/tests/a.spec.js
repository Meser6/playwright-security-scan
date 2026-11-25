import { test, expect } from '@playwright/test';

test('a', async ({ page }) => {
  await page.goto('/');
  expect(1).toBe(1);
});
