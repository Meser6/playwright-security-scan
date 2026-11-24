import { test as base } from '@playwright/test';
import type { BrowserContext } from '@playwright/test';
import { trackContext, withSecurityFixtures } from 'playwright-security-scan/fixture';

export { expect } from '@playwright/test';

const withWorkerContext = base.extend<object, { workerContext: BrowserContext }>({
  workerContext: [
    async ({ browser }, use) => {
      const context = await browser.newContext({ baseURL: process.env.BASE_URL });
      await trackContext(context);
      await use(context);
      await context.close();
    },
    { scope: 'worker' },
  ],
});

export const test = withSecurityFixtures(withWorkerContext);
