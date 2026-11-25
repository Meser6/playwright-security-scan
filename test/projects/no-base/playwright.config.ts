import { defineConfig } from '@playwright/test';
import { withSecurity } from 'playwright-security-scan/config';

// TEST_BROWSER: firefox or webkit in the informational browser cells of CI (10-AC-01).
const browser = (process.env.TEST_BROWSER ?? 'chromium') as 'chromium' | 'firefox' | 'webkit';

// No baseURL and no package config (03-AC-01).
export default withSecurity(
  defineConfig({
    testDir: './tests',
    reporter: [['json', { outputFile: 'results.json' }]],
    projects: [{ name: 'chromium', use: { browserName: browser } }],
  }),
);
