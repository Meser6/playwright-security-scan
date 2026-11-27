import { defineConfig } from '@playwright/test';
import { withSecurity } from 'playwright-security-scan/config';

// TEST_BROWSER: firefox or webkit in the informational browser cells of CI (10-AC-01).
const browser = (process.env.TEST_BROWSER ?? 'chromium') as 'chromium' | 'firefox' | 'webkit';

// One project per app instance (10-REQ-04, 10-REQ-05): APP_INSTANCES is a JSON list of
// { name, url, partner }; "secure" is the app without switches, the others have one switch each.
const instances = JSON.parse(process.env.APP_INSTANCES ?? '[]') as {
  name: string;
  url: string;
  partner: string;
}[];

export default withSecurity(
  defineConfig({
    testDir: './tests',
    fullyParallel: true,
    workers: 4,
    reporter: [['json', { outputFile: 'results.json' }]],
    use: { ignoreHTTPSErrors: true, browserName: browser },
    projects: instances.map((i) => ({
      name: i.name,
      use: { baseURL: i.url },
      metadata: { partner: i.partner },
    })),
  }),
  {
    // Every instance is its own origin; the strict preset reports the strict-only rules too. The
    // partner scripts are expected, the CDN script is not (asset.unexpected-third-party).
    scope: { origins: instances.map((i) => i.url) },
    rules: {
      preset: 'strict',
      'asset.unexpected-third-party': {
        options: { allowedScriptOrigins: instances.map((i) => i.partner) },
      },
    },
    gate: { failOnNoTraffic: false },
  },
);
