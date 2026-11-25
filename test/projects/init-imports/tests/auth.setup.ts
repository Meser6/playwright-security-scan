import { test as setup } from '@playwright/test';

setup('login', async ({ page }) => {
  await page.goto('/login');
});
