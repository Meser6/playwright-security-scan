import { defineConfig } from '@playwright/test';
import { withPerf } from 'playwright-performance-regression/config';
import { withSecurity } from 'playwright-security-scan/config';

// TEST_BROWSER: firefox or webkit in the informational browser cells of CI (10-AC-01).
const browser = (process.env.TEST_BROWSER ?? 'chromium') as 'chromium' | 'firefox' | 'webkit';

// withSecurity() is the outer config wrapper: in perf mode withPerf() keeps only the reporters it
// knows, so the security reporter is added after it. The fixture order is free (ORDER).
export default withSecurity(
  withPerf(
    defineConfig({
      testDir: './tests',
      workers: 1,
      reporter: [['json', { outputFile: 'results.json' }]],
      use: { baseURL: process.env.BASE_URL },
      projects: [{ name: 'chromium', use: { browserName: browser } }],
    }),
    { run: { keepReporters: ['json'] } },
  ),
);
