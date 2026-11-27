import { expect, test } from '../fixtures';

const PARTNER = process.env.PARTNER_URL ?? '';

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
  await page.goto(`/redirect?next=${encodeURIComponent(`${PARTNER}/landing`)}`);
  await expect(page.locator('body')).toBeVisible();
});

test('partner page calls the API', async ({ page }) => {
  await page.goto(`${PARTNER}/partner`);
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
  // The bodies are read: a body left unread is cancelled by the next navigation (05-REQ-09).
  const status = await page.evaluate(async () => {
    const login = await fetch('/api/login', { method: 'POST' });
    await login.text();
    await (await fetch('/api/me')).text();
    return login.status;
  });
  expect(status).toBe(200);
  await page.goto('/');
  // The subscribe form posted with its fields (the CSRF token in the secure mode).
  const subscribed = await page.evaluate(async () => {
    const form = document.querySelector<HTMLFormElement>('#subscribe');
    const body = new URLSearchParams();
    for (const [name, value] of new FormData(form ?? undefined)) body.append(name, String(value));
    const response = await fetch('/subscribe', { method: 'POST', body });
    await response.text();
    return response.ok;
  });
  expect(subscribed).toBe(true);
});
