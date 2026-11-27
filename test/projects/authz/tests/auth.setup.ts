import { test } from '@playwright/test';

// Signs in the three users of the authorization endpoints and saves their sessions.
for (const user of ['admin', 'bob', 'carol']) {
  test(`sign in ${user}`, async ({ request }) => {
    const response = await request.post(`/api/authz/login?user=${user}`);
    if (!response.ok()) throw new Error(`sign-in of ${user} failed: ${response.status()}`);
    await request.storageState({ path: `.auth/${user}.json` });
  });
}
