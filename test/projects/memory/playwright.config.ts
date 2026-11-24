import { defineConfig } from '@playwright/test';
import { withSecurity } from 'playwright-security-scan/config';

export default withSecurity(
  defineConfig({
    testDir: './tests',
    workers: 1,
    reporter: [['json', { outputFile: 'results.json' }]],
    use: { baseURL: process.env.BASE_URL },
    projects: [{ name: 'chromium', use: { browserName: 'chromium' } }],
  }),
);
