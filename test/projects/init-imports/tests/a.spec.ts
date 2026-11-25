import { test, expect, type Page } from '@playwright/test';

const open = (page: Page) => page.goto('/');

test('a', async ({ page }) => {
  await open(page);
  expect(1).toBe(1);
});
