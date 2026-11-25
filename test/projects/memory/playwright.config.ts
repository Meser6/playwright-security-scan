import { defineConfig } from '@playwright/test';
import { withSecurity } from 'playwright-security-scan/config';

// TEST_BROWSER: firefox or webkit in the informational browser cells of CI (10-AC-01).
const browser = (process.env.TEST_BROWSER ?? 'chromium') as 'chromium' | 'firefox' | 'webkit';

export default withSecurity(
  defineConfig({
    testDir: './tests',
    workers: 1,
    reporter: [['json', { outputFile: 'results.json' }]],
    use: { baseURL: process.env.BASE_URL },
    projects: [{ name: 'chromium', use: { browserName: browser } }],
  }),
);
