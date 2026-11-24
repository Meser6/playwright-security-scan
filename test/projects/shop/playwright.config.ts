import { defineConfig } from '@playwright/test';
import { withSecurity } from 'playwright-security-scan/config';

// The e2e and API tests of the reference app (10-REQ-02a). APP_URL is the app over HTTPS (or HTTP
// for transport.cleartext), PARTNER_URL another origin.
export default withSecurity(
  defineConfig({
    testDir: './tests',
    workers: 2,
    reporter: [['json', { outputFile: 'results.json' }]],
    use: { baseURL: process.env.APP_URL, ignoreHTTPSErrors: true },
    projects: [{ name: 'chromium', use: { browserName: 'chromium' } }],
  }),
  process.env.PW_SEC_PRESET === 'strict' ? { rules: { preset: 'strict' } } : undefined,
);
