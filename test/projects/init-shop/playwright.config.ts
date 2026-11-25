import { defineConfig } from '@playwright/test';

// TEST_BROWSER: firefox or webkit in the informational browser cells of CI (10-AC-01).
const browser = (process.env.TEST_BROWSER ?? 'chromium') as 'chromium' | 'firefox' | 'webkit';

// The reference app before the setup wizard ran (11-AC-02).
export default defineConfig({
  testDir: './tests',
  workers: 1,
  reporter: [['json', { outputFile: 'results.json' }]],
  use: { baseURL: process.env.APP_URL, ignoreHTTPSErrors: true },
  projects: [{ name: 'chromium', use: { browserName: browser } }],
});
