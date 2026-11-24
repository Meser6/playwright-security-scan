import { defineConfig } from '@playwright/test';
import { withSecurity } from 'playwright-security-scan/config';

// No baseURL and no package config (03-AC-01).
export default withSecurity(
  defineConfig({
    testDir: './tests',
    reporter: [['json', { outputFile: 'results.json' }]],
    projects: [{ name: 'chromium', use: { browserName: 'chromium' } }],
  }),
);
