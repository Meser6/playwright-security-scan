# Adopting the package in an existing project

The package works with the tests you have: it needs two changes in your files and nothing in your
tests themselves.

## The two changes

```ts
// playwright.config.ts
import { defineConfig } from '@playwright/test';
import { withSecurity } from 'playwright-security-scan/config';

export default withSecurity(defineConfig({/* your config, unchanged */}));
```

```ts
// fixtures.ts: the one place your tests import `test` from
import { test as base } from '@playwright/test';
import { withSecurityFixtures } from 'playwright-security-scan/fixture';

export { expect } from '@playwright/test';
export const test = withSecurityFixtures(base);
```

Without a fixture module, change the imports of your spec files instead:

```ts
import { test, expect } from 'playwright-security-scan/test';
```

`withSecurity()` adds the package reporter in a scan and validates the package config; it keeps
workers, retries, timeouts and your reporters. `withSecurityFixtures()` adds the scan to the
`context`, `page` and `request` fixtures and a `security` fixture. Without `PW_SEC_MODE` both
return what they got (the fixtures add only `security`, which does nothing).

Then run a [check](cli.md#dry-run-check): it tells you whether the scan sees your traffic.

## Situation → what to do

| Situation                                                                                       | What to do                                                                                                                                                                                                |
| ----------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Your own fixtures (`base.extend({...})`)                                                        | Wrap the result: `withSecurityFixtures(base.extend({...}))`, or extend the wrapped object. Both work; keep the wrapper last when your fixtures override `context` (below).                                |
| Several test objects (`test`, `adminTest`, …)                                                   | Wrap every object your tests use. An object derived from a wrapped one is scanned already; wrapping it again changes nothing. See [Several test objects](#several-test-objects).                          |
| `mergeTests(a, b)`                                                                              | Wrap the merged object: `withSecurityFixtures(mergeTests(a, b))`.                                                                                                                                         |
| playwright-bdd                                                                                  | Wrap the `test` you pass to `createBdd()`: `createBdd(withSecurityFixtures(test))`. The generated files import it from your steps file.                                                                   |
| API-only tests (`request` fixture)                                                              | Import `test` from the wrapped object, as in browser tests: every `request` call is analysed.                                                                                                             |
| Own API clients from `playwright.request.newContext()` (also in worker fixtures or `beforeAll`) | Call `trackRequestContext(context)` from `playwright-security-scan/fixture` right after creating it.                                                                                                      |
| `browser.newContext()` inside a test                                                            | `await security.track(context)`. Worker-scoped contexts: `await trackContext(context)`.                                                                                                                   |
| Login (`setup`) project                                                                         | Nothing; it is scanned like any project. Leave it out with `scope.projects` if its traffic is not interesting.                                                                                            |
| API on another origin than `baseURL`                                                            | Add it to `scope.origins`. The check lists the traffic outside the scope.                                                                                                                                 |
| Another wrapper around the Playwright config                                                    | Make `withSecurity()` the outermost call when the other wrapper changes the reporters (perf does: see below).                                                                                             |
| Own reporters (Allure, TestRail, Slack, JUnit)                                                  | Nothing: they stay. Only `--reporter` on the command line replaces every configured reporter; the run stops with [`RUN_REPORTER_FLAG`](troubleshooting.md#run_reporter_flag) and the flag to use instead. |
| `page.route()` mocks                                                                            | Mocked responses are skipped: they are not your server.                                                                                                                                                   |
| Firefox and WebKit projects                                                                     | Scanned too; Chromium is the reference browser (see [FAQ](faq.md#can-i-scan-firefox-or-webkit)).                                                                                                          |
| A JavaScript (CommonJS) config                                                                  | `const { withSecurity } = require('playwright-security-scan/config')`: every entry point ships ESM and CJS.                                                                                               |

### Order of `context` overrides

The package scans a browser context through its `context` fixture. If a fixture added **after**
`withSecurityFixtures()` overrides `context` without using the base `context`, the package never
sees that context; the `page` fixture still tracks the page's context. Keep the wrapper last, or
call `security.track(context)` in your override.

### Several test objects

A fixture module often exports two objects where one extends the other, e.g. `testNoAuth` and a
`test` that adds a logged-in `request`. Wrap the first and build the second on the wrapped one:

```ts
export const testNoAuth = withSecurityFixtures(base);
export const test = testNoAuth.extend<{ request: APIRequestContext }>({/* … */});
```

Both are scanned. Wrapping only the last one leaves `testNoAuth` unscanned; the report lists tests
without traffic, which is how you notice.

## Tests without traffic

A test that imports `test` straight from `@playwright/test` is not scanned: it runs normally and
the report lists it under tests without traffic (up to 50). So does a test whose traffic is all
outside the scope. When no response at all is in scope, the run ends with
[`NO_TRAFFIC`](troubleshooting.md#no_traffic).

## Start without blocking builds

Adopt in steps:

1. `PW_SEC_MODE=check` until the scope is right.
2. `PW_SEC_MODE=baseline`, review, commit the baseline.
3. Run `scan` in CI with `gate.minSeverity: 'high'` first, or as a job that may fail, and lower
   the gate when the team is used to the findings.

## Monorepos

Each Playwright config has its own package config, baseline and report directory, all relative to
that config. Run the scan per app, like your tests.

## Together with playwright-performance-regression

Both packages can be used in one project. Wrap the config with `withSecurity()` **outside**
`withPerf()` (in perf mode `withPerf()` keeps only the reporters it knows); the fixtures can be
chained in any order:

```ts
// playwright.config.ts
export default withSecurity(withPerf(defineConfig({/* … */})));

// fixtures.ts
export const test = withSecurityFixtures(withPerfFixtures(base));
```

Chain the wrappers rather than merging the ready `test` objects of both packages: both override the
same `context`, `page` and `request` fixtures.

In the reverse order (`withPerf(withSecurity(...))`) perf mode removes the security reporter:
nothing is scanned and the run still passes. After the first run, check that the console shows the
`playwright-security-scan · scan run` banner.

Run the two in separate CI jobs: analysing response bodies adds load that can distort timings. A
run with both `PW_SEC_MODE` and `PW_PERF_MODE` warns with
[`PERF_MODE_ACTIVE`](troubleshooting.md#perf_mode_active).
