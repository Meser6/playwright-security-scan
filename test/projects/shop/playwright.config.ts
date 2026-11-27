import { defineConfig } from '@playwright/test';
import { withSecurity } from 'playwright-security-scan/config';
import type { SecurityConfigInput } from 'playwright-security-scan/config';
import { broken, loginCookies, requestId } from './security-rules';

// TEST_BROWSER: firefox or webkit in the informational browser cells of CI (10-AC-01).
const browser = (process.env.TEST_BROWSER ?? 'chromium') as 'chromium' | 'firefox' | 'webkit';

// Custom rules (16): SHOP_CUSTOM_RULES=1, with the broken one also SHOP_CUSTOM_THROW=1.
// The partner script is expected (asset.unexpected-third-party); the CDN script is not.
const rules: NonNullable<SecurityConfigInput['rules']> = {
  ...(process.env.PW_SEC_PRESET === 'strict' ? { preset: 'strict' as const } : {}),
  ...(process.env.PARTNER_URL === undefined
    ? {}
    : {
        'asset.unexpected-third-party': {
          options: { allowedScriptOrigins: [process.env.PARTNER_URL] },
        },
      }),
  ...(process.env.SHOP_CUSTOM_RULES === '1'
    ? {
        custom: [
          requestId,
          loginCookies,
          ...(process.env.SHOP_CUSTOM_THROW === '1' ? [broken] : []),
        ],
        'custom.request-id-missing': { severity: 'medium' as const },
      }
    : {}),
};

// The e2e and API tests of the reference app (10-REQ-02a). APP_URL is the app over HTTPS (or HTTP
// for transport.cleartext), PARTNER_URL another origin.
export default withSecurity(
  defineConfig({
    testDir: './tests',
    workers: 2,
    reporter: [['json', { outputFile: 'results.json' }]],
    use: { baseURL: process.env.APP_URL, ignoreHTTPSErrors: true },
    projects: [{ name: 'chromium', use: { browserName: browser } }],
  }),
  Object.keys(rules).length === 0 ? undefined : { rules },
);
