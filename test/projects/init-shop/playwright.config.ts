import { defineConfig } from '@playwright/test';

// The reference app before the setup wizard ran (11-AC-02).
export default defineConfig({
  testDir: './tests',
  workers: 1,
  reporter: [['json', { outputFile: 'results.json' }]],
  use: { baseURL: process.env.APP_URL, ignoreHTTPSErrors: true },
  projects: [{ name: 'chromium', use: { browserName: 'chromium' } }],
});
