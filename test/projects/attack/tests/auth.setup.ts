import { test } from '@playwright/test';

// Signs in bob through the page (the API context cannot resolve a mapped host name) and saves
// the session for the customer project.
test('sign in bob', async ({ page }) => {
  await page.goto('/');
  const status = await page.evaluate(() =>
    fetch('/api/authz/login?user=bob', { method: 'POST' }).then((r) => r.status),
  );
  if (status !== 200) throw new Error(`sign-in failed: ${String(status)}`);
  await page.context().storageState({ path: '.auth/bob.json' });
});
