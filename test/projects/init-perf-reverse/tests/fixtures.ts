import { test as base } from '@playwright/test';
import { withSecurityFixtures } from 'playwright-security-scan/fixture';

export const test = withSecurityFixtures(base);
