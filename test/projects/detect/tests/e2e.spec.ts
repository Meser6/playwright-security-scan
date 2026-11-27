import { expect, test } from '../fixtures';

test('home page and navigation', async ({ page }) => {
  await page.goto('/');
  await expect(page.locator('h1')).toHaveText('Shop');
  await page.waitForLoadState('networkidle');
  await page.click('#account');
  await expect(page.locator('h1')).toHaveText('Account');
});

test('login, profile and token in the browser', async ({ page }) => {
  await page.goto('/account');
  const status = await page.evaluate(async () => {
    const login = await fetch('/api/login', { method: 'POST' });
    await fetch('/api/me');
    await fetch('/api/token');
    return login.status;
  });
  expect(status).toBe(200);
});

test('search', async ({ page }) => {
  await page.goto('/');
  await page.click('#search');
  await expect(page.locator('p')).toBeVisible();
});

test('redirect after login', async ({ page }) => {
  await page.goto(
    `/redirect?next=${encodeURIComponent(`${String(test.info().project.metadata.partner)}/landing`)}`,
  );
  await expect(page.locator('body')).toBeVisible();
});

test('partner page calls the API', async ({ page }) => {
  await page.goto(`${String(test.info().project.metadata.partner)}/partner`);
  await page.waitForFunction(
    () => (window as unknown as { done?: Promise<boolean> }).done !== undefined,
  );
  await page.evaluate(() => (window as unknown as { done: Promise<boolean> }).done);
});

test('error page and static directory', async ({ page }) => {
  await page.goto('/account');
  const statuses = await page.evaluate(async () => [
    (await fetch('/api/fail')).status,
    (await fetch('/static/')).status,
  ]);
  expect(statuses.every((s) => s >= 200)).toBe(true);
});

test('subscribe form', async ({ page }) => {
  await page.goto('/');
  await expect(page.locator('#subscribe')).toBeVisible();
});

test('sign-in page, login and subscribe', async ({ page }) => {
  await page.goto('/login');
  await expect(page.locator('#login')).toBeVisible();
  // No navigation after the calls: it would drop bodies the collector still reads (05-REQ-09).
  const result = await page.evaluate(async () => {
    const login = await fetch('/api/login', { method: 'POST' });
    await login.text();
    await (await fetch('/api/me')).text();
    // The subscribe form of the home page, posted with its fields (the CSRF token when secure).
    const html = await (await fetch('/')).text();
    const form = new DOMParser().parseFromString(html, 'text/html').querySelector('#subscribe');
    const body = new URLSearchParams();
    for (const input of Array.from(form?.querySelectorAll('input') ?? [])) {
      body.append(input.name, input.value);
    }
    const subscribe = await fetch('/subscribe?ajax=1', { method: 'POST', body });
    await subscribe.text();
    return [login.status, subscribe.status];
  });
  expect(result).toEqual([200, 204]);
});
