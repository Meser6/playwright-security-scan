import { defineConfig } from '@playwright/test';
import { withSecurity } from 'playwright-security-scan/config';

// API tests and one UI test on the same endpoints (10-REQ-02a).
export default withSecurity(
  defineConfig({
    testDir: './tests',
    workers: 1,
    reporter: [['json', { outputFile: 'results.json' }]],
    use: { baseURL: process.env.BASE_URL },
    projects: [{ name: 'api', use: { browserName: 'chromium' } }],
  }),
);
