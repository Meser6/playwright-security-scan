import { defineConfig } from '@playwright/test';
import { withPerf } from 'playwright-performance-regression/config';
import { withSecurity } from 'playwright-security-scan/config';
import perfConfig from './pw-perf.config';

export default withPerf(withSecurity(defineConfig({ testDir: './tests' })), perfConfig);
