import { test as base } from '@playwright/test';
import type { Page } from '@playwright/test';
import { withSecurityFixtures } from 'playwright-security-scan/fixture';

export { expect } from '@playwright/test';
export const test = withSecurityFixtures(base);

/**
 * Opens a page without waiting for the load event, then waits until the network is idle (every
 * subresource answered). Firefox now and then never reports load for a loaded page (10-AC-01).
 */
export async function open(page: Page, url: string): Promise<void> {
  await page.goto(url, { waitUntil: 'domcontentloaded' });
  await page.waitForLoadState('networkidle');
}
