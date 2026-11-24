import { test as base } from '@playwright/test';
import { withPerfFixtures } from 'playwright-performance-regression/fixture';
import { withSecurityFixtures } from 'playwright-security-scan/fixture';

export { expect } from '@playwright/test';

export const test =
  process.env.ORDER === 'perf-outer'
    ? withPerfFixtures(withSecurityFixtures(base))
    : withSecurityFixtures(withPerfFixtures(base));
