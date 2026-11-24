import { test as base } from '@playwright/test';
import { withSecurityFixtures } from 'playwright-security-scan/fixture';

// Reports the heap of the worker after all tests (NF-02).
const test = withSecurityFixtures(
  base.extend<object, { heap: void }>({
    heap: [
      // eslint-disable-next-line no-empty-pattern
      async ({}, use) => {
        await use();
        console.log(`PW_SEC_HEAP_MB=${Math.round(process.memoryUsage().heapUsed / 1048576)}`);
      },
      { scope: 'worker', auto: true },
    ],
  }),
);

for (let i = 0; i < 200; i++) {
  test(`page ${i}`, async ({ page }) => {
    await page.goto(i % 2 === 0 ? '/bundle' : '/page', { waitUntil: 'load' });
    await page.evaluate((n) => fetch(`/api/items/${n}`).then((r) => r.text()), i);
  });
}
