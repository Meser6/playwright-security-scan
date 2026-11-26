import { test as base } from '@playwright/test';

export { expect } from '@playwright/test';
export const test = base.extend<{ shop: string }>({
  shop: async ({}, use) => {
    await use('shop');
  },
});
