# playwright-security-scan

Passive security scan (DAST) of the HTTP traffic your existing Playwright tests already produce —
e2e tests in the browser and API tests with the `request` fixture. No proxy, no ZAP, no new
scenarios: run your usual test command with `PW_SEC_MODE=scan`, review the findings, accept the
current state into a committed baseline, and from then on the run fails only when a **new**
problem appears.

It checks security headers, cookies, CORS, transport, tokens and secrets, information disclosure
and what the browser itself reports (CSP violations, Web Storage), with
[44 rules](docs/rules/README.md) by default. Reports: console, HTML, JSON, SARIF (GitHub code
scanning) and JUnit XML (any CI).

> **Status:** beta, published under the `next` tag.

## What it does not do

- It is **passive**: it never sends a request of its own and never changes your tests' requests.
  So it does not test for injection, broken access control or other issues that need attacks;
  active checks are planned for later versions.
- It only sees what your tests visit. Endpoints no test calls are not checked.
- WebSockets, Server-Sent Events and service worker traffic are not analysed.
- It does **not** replace a penetration test or a dependency (SCA) scan. A green run means "nothing
  new since the last accepted baseline", not "the application is secure".

## Install

```sh
npm init playwright-security-scan@next
```

This installs the package as a dev dependency and starts a short guided setup: it asks for the
rule preset, the gate, the origins of your app, environments and your test command, shows a diff
of every change before writing it, offers a check run and ends with the exact commands for your
project. See [Guided setup](docs/init.md). To set it up by hand instead:

```sh
npm install --save-dev playwright-security-scan@next
```

## Set up by hand: two changes

```ts
// playwright.config.ts
import { defineConfig } from '@playwright/test';
import { withSecurity } from 'playwright-security-scan/config';

export default withSecurity(
  defineConfig({
    // your config, unchanged
  }),
);
```

```ts
// fixtures.ts — the one place your tests import `test` from
import { test as base } from '@playwright/test';
import { withSecurityFixtures } from 'playwright-security-scan/fixture';

export { expect } from '@playwright/test';
export const test = withSecurityFixtures(base);
```

No fixture module? Change the imports of your spec files to the ready one:

```ts
// before: import { test, expect } from '@playwright/test';
import { test, expect } from 'playwright-security-scan/test';
```

Without `PW_SEC_MODE` nothing changes. The scope is the origin of `use.baseURL` of each project;
add your API's origin with `scope.origins` if it runs elsewhere. Own fixtures, several test
objects, `mergeTests`, playwright-bdd and the perf package: see [Adoption](docs/adoption.md).

## Use

```sh
# 0. Dry run: does the scan see your traffic?
PW_SEC_MODE=check npx playwright test

# 1. First run: accept the current state as the baseline
PW_SEC_MODE=baseline npx playwright test

# 2. Review security-baseline.json and the report, add a "note" to each entry you accept, commit
git add security-baseline.json && git commit -m "Accept the current security findings"

# 3. In CI (and locally): fail only on new findings at or above the gate (medium by default)
PW_SEC_MODE=scan npx playwright test
```

On Windows use `npx cross-env PW_SEC_MODE=scan npx playwright test` (see
[Running the scan](docs/cli.md#windows)). The result is in `reports/pw-sec/outcome.json`:

| Code | Name               | Meaning                                                                |
| ---- | ------------------ | ---------------------------------------------------------------------- |
| 0    | `OK`               | No new finding at or above the gate.                                   |
| 1    | `NEW_FINDINGS`     | At least one new finding at or above the gate.                         |
| 2    | `BASELINE_EXPIRED` | A baseline entry passed its `until` date and the finding still occurs. |
| 3    | `TOOL_ERROR`       | The scan could not be trusted (e.g. an invalid baseline file).         |
| 4    | `NO_TRAFFIC`       | No response was in scope: set `use.baseURL` or `scope.origins`.        |

Any code other than 0 makes the Playwright command exit with 1.

## Documentation

- [Guided setup](docs/init.md): `npm init playwright-security-scan`
- [Running the scan](docs/cli.md): modes, variables, Windows, the check, exit codes, colors
- [Configuration](docs/configuration.md): every option
- [The baseline](docs/baseline.md): workflow, statuses, expiry, partial runs, environments
- [Rules](docs/rules/README.md): what each rule checks, how to fix it, false positives
- [Reports](docs/reports.md): HTML, JSON, SARIF, JUnit, privacy of the evidence
- [CI](docs/ci.md): GitHub Actions, GitLab, Azure DevOps, Jenkins
- [Adoption](docs/adoption.md): existing fixtures, setups and the perf package
- [Troubleshooting](docs/troubleshooting.md): every code the package reports
- [FAQ](docs/faq.md) · [Upgrading](docs/upgrading.md) · [Changelog](CHANGELOG.md)

## Privacy

The package sends nothing anywhere: no telemetry, no network calls of its own, and the HTML report
loads nothing from the network. Evidence is redacted before it leaves the test worker.

## License

MIT
