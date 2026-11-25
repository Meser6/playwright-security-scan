import { defineConfig } from '@playwright/test';
import { withPerf } from 'playwright-performance-regression/config';
import perfConfig from './pw-perf.config';

export default withPerf(defineConfig({ testDir: './tests' }), perfConfig);
