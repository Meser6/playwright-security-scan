import { test as base } from '@playwright/test';

export { expect } from '@playwright/test';
export const test = base.extend<{ user: string }>({
  user: async ({}, use) => {
    await use('alice');
  },
});
