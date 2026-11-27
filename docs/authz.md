# Authorization tests

Broken access control is the most common real vulnerability of web APIs (OWASP A01: IDOR/BOLA,
endpoints without a session check, admin functions open to normal users). Your Playwright project
already knows your roles: projects with a `storageState`. With the authorization tests on, the
package replays the **GET and HEAD requests your tests made** after the tests, as other roles and
without a session, and reports when the answer is the same as the one of the user who was allowed
to see it.

They are **off by default** and the only requests the package ever sends itself. Turn them on only
for a test environment.

## Turn them on

```ts
// pw-sec.config.ts
import { defineSecurityConfig } from 'playwright-security-scan/config';

export default defineSecurityConfig({
  authz: {
    enabled: true,
    // Required, no default: the only origins the package may send requests to.
    allowedOrigins: ['https://staging.example.com'],
    roles: {
      admin: { level: 1 },
      customer: { level: 0 },
      customer2: { role: 'customer', level: 0 },
    },
  },
});
```

The replays run in `scan` and `baseline` runs, after the last test, in the reporter. A check
(`PW_SEC_MODE=check`) sends nothing: it prints the roles, the number of request templates and the
replays it would plan. `PW_SEC_AUTHZ=0` switches the tests off for one run without changing the
config (the start banner says `Authz  disabled by PW_SEC_AUTHZ=0`).

## Safety

- **Only GET and HEAD.** Requests that change data (`POST`, `PUT`, `PATCH`, `DELETE`) are never
  replayed. Logout URLs (`logout`, `signout`, `sign-out`, `log-out` in the path) and URLs with
  token parameters are left out.
- **Only allowed origins.** `authz.allowedOrigins` has no default; without it the run stops before
  the tests (`AUTHZ_ORIGINS_REQUIRED`). A request to any other origin is refused in the code that
  sends it, also after a redirect: redirects are never followed.
- **Never production.** An allowed origin that starts with `www.`, has a `prod` or `production`
  part, or is a domain without a subdomain (`shop.com`) stops the run (`AUTHZ_ORIGIN_DENIED`).
  `authz.iUnderstandThisIsNotProduction: true` lifts the built-in patterns for a test environment on
  such a domain; `authz.denyOrigins` can never be lifted.
- **A budget.** At most `authz.maxRequests` requests (500), `authz.maxRps` per second (5) and
  `authz.maxDurationMinutes` (10); the rest is skipped with `AUTHZ_BUDGET_EXCEEDED`.
- **Marked.** Every request carries `x-pw-sec-probe: <run id>`, so you can find it in logs and in
  the WAF (`authz.probeHeader: false` removes it).
- **Only URLs your tests called.** The package never guesses or changes ids.
- **No bodies on disk.** The worker keeps a template of each request without cookies or
  credential headers and a digest of the answer: salted hashes of the JSON keys and values or of
  the words of a page, never the text. The replay answers stay in memory.

## Roles

A role is a project with `use.storageState` set to a file path. The role name is the project name;
there is always the role `anonymous` (no cookies, no credential headers).

| `authz.roles.<project>` | Meaning                                                                                                         |
| ----------------------- | --------------------------------------------------------------------------------------------------------------- |
| `role`                  | A shared role name: two projects with different users of one role (needed for the IDOR test)                    |
| `level`                 | Permission level for the vertical test; higher = more permissions; without it the role is not tested vertically |
| `headers`               | Credential headers of the role, e.g. `{ authorization: \`Bearer ${process.env.CUSTOMER_TOKEN}\` }`              |
| `skip`                  | The project is not a role                                                                                       |

A replay as a role uses the cookies of its `storageState` file (read after the tests, so the setup
project has written it) and its `headers`. A request that carried an `Authorization` header is
replayed as another role only when that role has `headers.authorization`.

### A second user

The IDOR test (`authz.horizontal`) needs two users of one role. Sign in a second user in the setup
project and add a project for it:

```ts
// auth.setup.ts
setup('customer', async ({ page }) => {
  /* sign in user A */ await page.context().storageState({ path: '.auth/customer.json' });
});
setup('customer2', async ({ page }) => {
  /* sign in user B */ await page.context().storageState({ path: '.auth/customer2.json' });
});

// playwright.config.ts
projects: [
  { name: 'setup', testMatch: /auth\.setup\.ts/ },
  { name: 'customer', dependencies: ['setup'], use: { storageState: '.auth/customer.json' } },
  { name: 'customer2', dependencies: ['setup'], use: { storageState: '.auth/customer2.json' } },
],

// pw-sec.config.ts
authz: { roles: { customer2: { role: 'customer' } } }
```

Without a pair the coverage says `horizontal: needs two users of one role`.

## The three tests

| Test                                                                    | Replayed request                                            | As                                                                    |
| ----------------------------------------------------------------------- | ----------------------------------------------------------- | --------------------------------------------------------------------- |
| [`authz.unauthenticated-access`](rules/authz.unauthenticated-access.md) | every request that carried a session                        | `anonymous`                                                           |
| [`authz.horizontal`](rules/authz.horizontal.md)                         | a request with an object id (`:id` in the key, an id query) | every other project of the same role                                  |
| [`authz.vertical`](rules/authz.vertical.md)                             | a request of a role with a `level`                          | every role with a lower `level` that never got this endpoint in tests |

An endpoint seen in the run with a 2xx answer **without** credentials (a guest project, a public
page) is public and is not tested without a session or for IDOR. `authz.tests: { horizontal: false }`
or `rules: { 'authz.horizontal': 'off' }` switch a test off (no requests are sent for it);
`authz.exclude: ['GET */api/shared/*']` leaves endpoint keys out (`*` within a path segment, a
pattern without a method matches every method).

A replay is **denied** for 401, 403, 404, 405, a redirect (the sign-in page), 5xx, an empty list, or
a page with a password field or "login" / "sign in" in the title. It is **similar** when it has a
2xx status and the same kind of body with a similarity of at least `authz.similarity` (0.8): for
JSON both the key structure and the key + value pairs, for pages the words. Only a similar answer
is a finding. The confidence is `high` when the answer carries an identifier of the original user
(the `sub`/`email` claim of its JWT, its e-mail in a `me`/`profile`/`account` answer), `low` when
the body could not be compared (only status and length).

## Results

Findings of `authz.*` work like any other: the baseline, the gate, accepted and false-positive
entries, SARIF and JUnit (group `authz`). The fingerprint names the role pair, never a value:
`authz.horizontal|endpoint|GET /api/invoices/:id|customer->customer`. An `authz.*` baseline entry
is resolved only when the run replayed that pair on that endpoint and got a denial or another
answer; with the tests off, `PW_SEC_AUTHZ=0` or a skipped replay it is not covered.

The HTML report has an **Authorization** tab: the roles, templates, replays and budget, and a
matrix of endpoints by role pair with `enforced`, `bypassed` (opens the finding), `different`,
`public` and `skipped (<reason>)`. `report.json` has the same in `authz`.

With [sharded runs](ci.md#sharded-runs) every shard replays the templates of its own tests (the
`storageState` files are on its machine; the budget counts per shard) and the merge judges them
with the knowledge of all shards.

## Options

| Option                                 | Default    | Meaning                                                   |
| -------------------------------------- | ---------- | --------------------------------------------------------- |
| `authz.enabled`                        | `false`    | Run the authorization tests in `scan` and `baseline` runs |
| `authz.allowedOrigins`                 | **none**   | Exact origins that may get the replays; required          |
| `authz.denyOrigins`                    | `[]`       | Origins that never get a request                          |
| `authz.iUnderstandThisIsNotProduction` | `false`    | Lift the built-in production patterns                     |
| `authz.roles`                          | `{}`       | Role options per project (see [Roles](#roles))            |
| `authz.exclude`                        | `[]`       | Endpoint key patterns not replayed                        |
| `authz.maxRequests`                    | `500`      | Requests per run (per shard)                              |
| `authz.maxRps`                         | `5`        | Requests per second                                       |
| `authz.maxDurationMinutes`             | `10`       | Time of the replays                                       |
| `authz.similarity`                     | `0.8`      | Threshold from 0 to 1 for a similar answer                |
| `authz.probeHeader`                    | `true`     | Send `x-pw-sec-probe: <run id>`                           |
| `authz.tests`                          | all `true` | `{ unauthenticated, horizontal, vertical }`               |

Codes: see [Authorization tests in the troubleshooting](troubleshooting.md#authorization-tests).
