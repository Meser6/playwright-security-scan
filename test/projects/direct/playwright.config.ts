import { defineConfig } from '@playwright/test';
import { withSecurity } from 'playwright-security-scan/config';

// Tests import `test` from playwright-security-scan/test, without a fixture module (01-REQ-12).
export default withSecurity(
  defineConfig({
    testDir: './tests',
    workers: 1,
    reporter: [['json', { outputFile: 'results.json' }]],
    use: { baseURL: process.env.APP_URL, ignoreHTTPSErrors: true },
    projects: [{ name: 'chromium', use: { browserName: 'chromium' } }],
  }),
);
