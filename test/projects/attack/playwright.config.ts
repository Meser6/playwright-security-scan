import { defineConfig } from '@playwright/test';
import { withSecurity } from 'playwright-security-scan/config';
import type { SecurityConfigInput } from 'playwright-security-scan/config';

// The attack mode (19, chapter 11a) on the reference app only: a setup project signs in bob, the
// project customer uses his storageState and is the scan role. ATTACK=1 sets attack.allowedOrigins
// to the reference app (APP_URL); ZAP_URL is a ZAP the test started on 127.0.0.1 (19-AC-06).
// PARTNER_URL is in the scan scope but never in attack.allowedOrigins (19-AC-03).
const app = process.env.APP_URL ?? '';
// On macOS the test reaches the local app through host.docker.internal (the host loopback, as
// Docker Desktop maps it): the browser resolves that name to 127.0.0.1 too.
const host = app === '' ? 'localhost' : new URL(app).hostname;
const launchOptions =
  host === 'localhost' ? {} : { args: [`--host-resolver-rules=MAP ${host} 127.0.0.1`] };
const attack: SecurityConfigInput['attack'] =
  process.env.ATTACK === '1'
    ? {
        allowedOrigins: [app],
        maxRps: 50,
        maxDurationMinutes: 10,
        ...(process.env.ZAP_URL === undefined ? {} : { zapUrl: process.env.ZAP_URL }),
      }
    : undefined;

export default withSecurity(
  defineConfig({
    testDir: './tests',
    workers: 1,
    reporter: [['json', { outputFile: 'results.json' }]],
    use: { baseURL: app, ignoreHTTPSErrors: true, launchOptions },
    projects: [
      { name: 'setup', testMatch: /auth\.setup\.ts/ },
      {
        name: 'customer',
        testMatch: /customer\.spec\.ts/,
        dependencies: ['setup'],
        use: { storageState: '.auth/bob.json' },
      },
    ],
  }),
  {
    scope: {
      projects: ['customer'],
      origins: process.env.PARTNER_URL === undefined ? [] : [process.env.PARTNER_URL],
    },
    ...(attack === undefined ? {} : { attack }),
  },
);
