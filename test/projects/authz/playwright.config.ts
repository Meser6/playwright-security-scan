import { defineConfig } from '@playwright/test';
import { withSecurity } from 'playwright-security-scan/config';
import type { SecurityConfigInput } from 'playwright-security-scan/config';

// The authorization tests (18, chapter 11) on the reference app: a setup project signs in three
// users, the projects admin, customer and customer2 use their storageState, guest has none.
// AUTHZ=1 turns the tests on; AUTHZ_MAX_REQUESTS sets the budget; PARTNER_URL is in the scan scope
// but not in authz.allowedOrigins (18-AC-04).
// TEST_BROWSER: firefox or webkit in the informational browser cells of CI (10-AC-01).
const browser = (process.env.TEST_BROWSER ?? 'chromium') as 'chromium' | 'firefox' | 'webkit';
const app = process.env.APP_URL ?? '';
const authz: SecurityConfigInput['authz'] =
  process.env.AUTHZ === '1'
    ? {
        enabled: true,
        allowedOrigins: [app],
        maxRps: 50,
        ...(process.env.AUTHZ_MAX_REQUESTS === undefined
          ? {}
          : { maxRequests: Number(process.env.AUTHZ_MAX_REQUESTS) }),
        roles: {
          admin: { level: 1 },
          customer: { level: 0 },
          customer2: { role: 'customer', level: 0 },
        },
      }
    : undefined;

const role = (name: string, user: string) => ({
  name,
  testMatch: new RegExp(`${name}\\.spec\\.ts`),
  dependencies: ['setup'],
  use: { browserName: browser, storageState: `.auth/${user}.json` },
});

export default withSecurity(
  defineConfig({
    testDir: './tests',
    workers: 2,
    reporter: [['json', { outputFile: 'results.json' }]],
    use: { baseURL: app, ignoreHTTPSErrors: true },
    projects: [
      { name: 'setup', testMatch: /auth\.setup\.ts/ },
      role('admin', 'admin'),
      role('customer', 'bob'),
      role('customer2', 'carol'),
      { name: 'guest', testMatch: /guest\.spec\.ts/, use: { browserName: browser } },
    ],
  }),
  {
    scope: { origins: process.env.PARTNER_URL === undefined ? [] : [process.env.PARTNER_URL] },
    ...(authz === undefined ? {} : { authz }),
  },
);
