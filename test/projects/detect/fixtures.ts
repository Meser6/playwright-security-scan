import { test as base } from '@playwright/test';
import type { Page } from '@playwright/test';
import { withSecurityFixtures } from 'playwright-security-scan/fixture';

export { expect } from '@playwright/test';
export const test = withSecurityFixtures(base);

/**
 * Opens a page in a way that does not lose the navigation in Firefox (10-AC-01): a goto() that
 * starts while the initial about:blank of a new page is still loading now and then never gets its
 * lifecycle events there. So the initial load is awaited first; then the test waits until the
 * network is idle (every subresource answered).
 */
export async function open(page: Page, url: string): Promise<void> {
  await page.waitForLoadState('load');
  await page.goto(url, { waitUntil: 'domcontentloaded' });
  await page.waitForLoadState('networkidle');
}
