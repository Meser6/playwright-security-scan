import { test as base } from '@playwright/test';
import { withSecurityFixtures } from 'playwright-security-scan/fixture';

export { expect } from '@playwright/test';
export const test = withSecurityFixtures(base);
