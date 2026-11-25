// Entry point `playwright-security-scan/test` (01-REQ-12): a ready `test` for projects that import
// it straight from @playwright/test. The only entry point that imports @playwright/test at runtime.
import { test as base } from '@playwright/test';
import { withSecurityFixtures } from '../fixture/index.ts';

export const test = withSecurityFixtures(base);
export { expect } from '@playwright/test';
