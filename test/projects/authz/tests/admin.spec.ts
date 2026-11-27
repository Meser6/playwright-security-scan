import { expect, test } from '../fixtures';

test('admin lists the users', async ({ page }) => {
  await page.goto('/');
  const users = await page.evaluate(() => fetch('/api/admin/users').then((r) => r.json()));
  expect(users.users).toHaveLength(3);
});
