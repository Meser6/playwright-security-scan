import { defineConfig } from '@playwright/test';
import { withCompany } from '@company/playwright';

export default withCompany(defineConfig({ testDir: './tests' }));
