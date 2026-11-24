import { test } from '@playwright/test';
import { withSecurityFixtures } from 'playwright-security-scan/fixture';

const t = withSecurityFixtures(test);

t('opens a page by its full URL', async ({ page }) => {
  await page.goto(`${process.env.BASE_URL}/page`);
});
