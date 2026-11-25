# playwright-security-scan

Passive security scan (DAST) of the HTTP traffic your existing Playwright tests already produce —
e2e tests in the browser and API tests with the `request` fixture. No proxy, no ZAP, no new
scenarios: run your usual test command with `PW_SEC_MODE=scan`, review the findings, accept the
current state into a committed baseline, and from then on the run fails only when a **new**
problem appears.

It checks security headers, cookies, CORS, transport, tokens and secrets, information disclosure
and what the browser itself reports (CSP violations, Web Storage), with 44 rules by default.
Reports: console, HTML, JSON, SARIF (GitHub code scanning) and JUnit XML (any CI).

> **Status:** pre-release, not published on npm yet.

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
npm install --save-dev playwright-security-scan
```

Requires Node.js ≥ 22.18 and `@playwright/test` ≥ 1.57. No runtime dependencies.

## Set up: two changes

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

If your specs import `test` from `@playwright/test` directly, create `fixtures.ts` as above and
change those imports to `./fixtures`. Without `PW_SEC_MODE` both wrappers change nothing.

The scope is the origin of `use.baseURL` of each project. If your API runs on another origin, add
it in a config file (see [Configuration](#configuration)).

## Use

```sh
# 1. First run: accept the current state as the baseline
PW_SEC_MODE=baseline npx playwright test

# 2. Review security-baseline.json and the report, add a "note" to each entry you accept, commit
git add security-baseline.json && git commit -m "Accept the current security findings"

# 3. In CI (and locally): fail only on new findings at or above the gate (medium by default)
PW_SEC_MODE=scan npx playwright test
```

On Windows use `cross-env PW_SEC_MODE=scan npx playwright test` or, in PowerShell,
`$env:PW_SEC_MODE="scan"; npx playwright test`.

| `PW_SEC_MODE` | What happens                                                                                 |
| ------------- | -------------------------------------------------------------------------------------------- |
| (unset)       | Nothing: the package adds no listener, no script and no reporter.                            |
| `scan`        | Analyses the traffic, compares with the baseline, writes the reports, fails on new findings. |
| `baseline`    | The same analysis without failing; writes `security-baseline.json` and prints the diff.      |

A `baseline` run filtered with `--grep`, `--project`, `--shard`, file arguments or `--only-changed`
keeps the entries it could not confirm as resolved. Avoid `test.only` in a baseline run.

### Result codes

`reports/pw-sec/outcome.json` tells CI why a scan failed, separately from your tests:

| Code | Name               | Meaning                                                                      |
| ---- | ------------------ | ---------------------------------------------------------------------------- |
| 0    | `OK`               | No new finding at or above the gate.                                         |
| 1    | `NEW_FINDINGS`     | At least one new finding at or above the gate.                               |
| 2    | `BASELINE_EXPIRED` | A baseline entry passed its `until` date and the finding still occurs.       |
| 3    | `TOOL_ERROR`       | The scan could not be trusted (e.g. an invalid baseline file); see the logs. |
| 4    | `NO_TRAFFIC`       | No response was in scope: set `use.baseURL` or `scope.origins`.              |

Any code other than 0 makes the Playwright command exit with 1. See
[docs/troubleshooting.md](docs/troubleshooting.md) for every code.

### Console output

The run starts with a banner (mode, scope, rules, gate, baseline, report) and ends with a summary
of at most 30 lines: errors and warnings in boxes, the counters and the blocking findings in
tables, the verdict in a box (`✅ PASSED`, `⚠ PASSED WITH WARNINGS`, `❌ FAILED`, `❌ ERROR`) with
the result name and code, and one `Report:` line with the absolute path of the HTML report.

Colors are used in a terminal whose `TERM` is not `dumb`. Every colored item also has an emoji
or a word, so the text is the same without colors.

| Variable        | Effect                                                       |
| --------------- | ------------------------------------------------------------ |
| `NO_COLOR=1`    | No colors, also in a terminal and with `FORCE_COLOR`.        |
| `FORCE_COLOR=1` | Colors also without a terminal (for example in CI logs).     |
| `FORCE_COLOR=0` | No colors.                                                   |
| `TERM=dumb`     | No colors, ASCII frames (`+`, `-`, `\|`), `✔ ! ✖` for emoji. |

## The baseline

`security-baseline.json` lists the findings you have decided about, one entry per fingerprint:

```json
{
  "schemaVersion": 1,
  "findings": {
    "cookie.no-httponly|cookie|session_id@app.example.com": {
      "ruleId": "cookie.no-httponly",
      "subject": "session_id@app.example.com",
      "severity": "medium",
      "status": "accepted",
      "note": "The frontend reads the cookie; ticket SEC-123",
      "until": "2027-02-01",
      "addedAt": "2026-11-24"
    }
  }
}
```

- `status`: `accepted` (risk accepted), `wontfix` (needs a `note`) or `false-positive` (never
  expires).
- `until` (optional): after this date the entry no longer protects the finding (code 2).
- The file holds no evidence, no URLs with values and no test names, so diffs stay small. Merge
  conflicts: keep both sides and run `PW_SEC_MODE=baseline` again.

## Configuration

Everything is optional. Pass a config as the second argument of `withSecurity()`, or point
`PW_SEC_CONFIG` to a file:

```ts
// pw-sec.config.ts
import { defineSecurityConfig } from 'playwright-security-scan/config';

export default defineSecurityConfig({
  scope: {
    origins: ['https://api.example.com'], // more origins of your app besides use.baseURL
    exclude: ['https://*.google-analytics.com'],
  },
  rules: {
    'header.referrer-policy-unsafe': 'off',
    'cookie.samesite-missing': { severity: 'info' },
    'data.token-in-url': { options: { paramNames: ['token', 'access_token', 'sig'] } },
  },
  gate: { minSeverity: 'medium', minConfidence: 'medium' },
});
```

| Option                                                        | Default                    | What it does                                                      |
| ------------------------------------------------------------- | -------------------------- | ----------------------------------------------------------------- |
| `scope.origins`                                               | `[]`                       | Origins to scan besides `use.baseURL` (`*` allowed in subdomains) |
| `scope.includeBaseURL`                                        | `true`                     | Scan the origin of `use.baseURL`                                  |
| `scope.exclude`                                               | `[]`                       | Origins never scanned                                             |
| `scope.projects`                                              | `'all'`                    | Playwright projects to scan (setup projects included)             |
| `scope.api`                                                   | `true`                     | Scan `APIRequestContext` calls                                    |
| `rules.preset`                                                | `'recommended'`            | `minimal` (high-confidence rules), `recommended`, `strict`        |
| `rules['<id>']`                                               | on                         | `'off'`, `'on'` or `{ severity, confidence, options }`            |
| `limits.maxBodyBytes`                                         | `1048576`                  | Longer bodies are cut before analysis                             |
| `limits.bodyContentTypes`                                     | HTML, JSON, JS, text, XML  | Content types whose bodies are read                               |
| `limits.maxFindingsPerRule`                                   | `200`                      | Per test                                                          |
| `browser.cspEvents` / `browser.storageScan`                   | `true`                     | CSP violation listener / Web Storage scan at the end of a test    |
| `gate.minSeverity` / `gate.minConfidence`                     | `'medium'` / `'medium'`    | The lowest new finding that fails the scan                        |
| `gate.failOnExpired` / `gate.failOnNoTraffic`                 | `true` / `true`            | Codes 2 and 4 fail the run                                        |
| `baseline.path`                                               | `'security-baseline.json'` | Relative to the Playwright config                                 |
| `baseline.pruneResolved` / `baseline.requireNote`             | `true` / `false`           | Remove resolved entries / require a note on accepted entries      |
| `report.dir`                                                  | `'reports/pw-sec'`         | Where reports go                                                  |
| `report.html` / `json` / `sarif` / `junit`                    | `true`                     | Which reports to write                                            |
| `report.junitPath`                                            | `<report.dir>/junit.xml`   | For CI artifact patterns                                          |
| `report.junitIncludeAccepted` / `report.sarifIncludeAccepted` | `true` / `false`           | Baseline entries in JUnit (skipped) and SARIF (suppressed)        |
| `normalization`                                               | as the perf package        | How URLs become endpoint keys (`GET /api/items/:id`)              |

Mistyped options and rule ids fail at once with the closest valid name.

### Contexts created by hand

Contexts from `browser.newContext()` inside a test are scanned after
`await security.track(context)`; worker-scoped contexts after `await trackContext(context)` (from
`playwright-security-scan/fixture`); contexts from `playwright.request.newContext()` after
`trackRequestContext(context)`.

## Rules

<!-- rules:start -->

| Rule                                                                                                                                     | Severity | Confidence | Traffic      | CWE     |
| ---------------------------------------------------------------------------------------------------------------------------------------- | -------- | ---------- | ------------ | ------- |
| [`header.csp-missing`](docs/rules/header.csp-missing.md) — Content-Security-Policy missing                                               | medium   | high       | browser      | 693     |
| [`header.csp-unsafe`](docs/rules/header.csp-unsafe.md) — Unsafe Content-Security-Policy                                                  | medium   | high       | browser      | 693     |
| [`header.csp-missing-directives`](docs/rules/header.csp-missing-directives.md) — CSP without object-src or base-uri                      | low      | high       | browser      | 693     |
| [`header.csp-report-only`](docs/rules/header.csp-report-only.md) — CSP in report-only mode only                                          | info     | high       | browser      | 693     |
| [`header.clickjacking`](docs/rules/header.clickjacking.md) — No clickjacking protection                                                  | medium   | medium     | browser      | 1021    |
| [`header.hsts-missing`](docs/rules/header.hsts-missing.md) — Strict-Transport-Security missing                                           | low      | high       | browser, api | 319     |
| [`header.hsts-weak`](docs/rules/header.hsts-weak.md) — Strict-Transport-Security max-age too short                                       | low      | high       | browser, api | 319     |
| [`header.xcto-missing`](docs/rules/header.xcto-missing.md) — X-Content-Type-Options: nosniff missing                                     | low      | high       | browser, api | 693     |
| [`header.referrer-policy-unsafe`](docs/rules/header.referrer-policy-unsafe.md) — Unsafe Referrer-Policy                                  | low      | high       | browser      | 200     |
| [`header.content-type-missing`](docs/rules/header.content-type-missing.md) — Content-Type missing                                        | low      | high       | browser, api | 16      |
| [`header.permissions-policy-missing`](docs/rules/header.permissions-policy-missing.md) (strict) — Permissions-Policy missing             | info     | high       | browser      | 693     |
| [`header.coop-missing`](docs/rules/header.coop-missing.md) (strict) — Cross-Origin-Opener-Policy missing                                 | info     | high       | browser      | 693     |
| [`cookie.no-secure`](docs/rules/cookie.no-secure.md) — Session cookie without Secure                                                     | medium   | high       | browser, api | 614     |
| [`cookie.no-httponly`](docs/rules/cookie.no-httponly.md) — Session cookie without HttpOnly                                               | medium   | high       | browser, api | 1004    |
| [`cookie.samesite-none`](docs/rules/cookie.samesite-none.md) — Session cookie with SameSite=None                                         | low      | medium     | browser, api | 1275    |
| [`cookie.samesite-missing`](docs/rules/cookie.samesite-missing.md) — Cookie without SameSite                                             | info     | high       | browser, api | 1275    |
| [`cookie.long-lived-session`](docs/rules/cookie.long-lived-session.md) — Long-lived session cookie                                       | low      | medium     | browser, api | 613     |
| [`cookie.non-session-insecure`](docs/rules/cookie.non-session-insecure.md) — Cookie without Secure                                       | info     | medium     | browser, api | 614     |
| [`cors.wildcard-credentials`](docs/rules/cors.wildcard-credentials.md) — CORS wildcard with credentials                                  | high     | high       | browser, api | 942     |
| [`cors.reflected-origin-credentials`](docs/rules/cors.reflected-origin-credentials.md) — CORS reflects a foreign origin with credentials | high     | medium     | browser, api | 942     |
| [`cors.null-origin`](docs/rules/cors.null-origin.md) — CORS allows the null origin                                                       | medium   | high       | browser, api | 942     |
| [`cors.wildcard-sensitive`](docs/rules/cors.wildcard-sensitive.md) — CORS wildcard on an authenticated endpoint                          | low      | low        | browser, api | 942     |
| [`transport.cleartext`](docs/rules/transport.cleartext.md) — Application served over HTTP                                                | medium   | high       | browser, api | 319     |
| [`transport.mixed-content`](docs/rules/transport.mixed-content.md) — Mixed content                                                       | medium   | high       | browser      | 311     |
| [`transport.form-to-http`](docs/rules/transport.form-to-http.md) — Form submits over HTTP                                                | medium   | high       | browser      | 319     |
| [`transport.weak-tls`](docs/rules/transport.weak-tls.md) — Outdated TLS version                                                          | medium   | high       | browser      | 326     |
| [`data.token-in-url`](docs/rules/data.token-in-url.md) — Token in URL                                                                    | medium   | high       | browser, api | 598     |
| [`data.jwt-alg-none`](docs/rules/data.jwt-alg-none.md) — JWT with alg none                                                               | critical | high       | browser, api | 347     |
| [`data.jwt-no-exp`](docs/rules/data.jwt-no-exp.md) — JWT without expiry                                                                  | medium   | high       | browser, api | 613     |
| [`data.jwt-long-lived`](docs/rules/data.jwt-long-lived.md) — Long-lived JWT                                                              | low      | high       | browser, api | 613     |
| [`data.jwt-sensitive-claims`](docs/rules/data.jwt-sensitive-claims.md) — Sensitive data in JWT claims                                    | medium   | medium     | browser, api | 312     |
| [`data.password-in-response`](docs/rules/data.password-in-response.md) — Password or hash in a response                                  | high     | medium     | browser, api | 200     |
| [`data.secret-in-asset`](docs/rules/data.secret-in-asset.md) — Secret in a script, page or response                                      | high     | high       | browser, api | 798     |
| [`data.token-in-storage`](docs/rules/data.token-in-storage.md) — Token in Web Storage                                                    | low      | medium     | browser      | 922     |
| [`disclosure.stack-trace`](docs/rules/disclosure.stack-trace.md) — Stack trace in a response                                             | medium   | high       | browser, api | 209     |
| [`disclosure.sql-error`](docs/rules/disclosure.sql-error.md) — SQL error in a response                                                   | high     | medium     | browser, api | 209, 89 |
| [`disclosure.server-version`](docs/rules/disclosure.server-version.md) — Server version disclosed                                        | low      | high       | browser, api | 200     |
| [`disclosure.debug-mode`](docs/rules/disclosure.debug-mode.md) — Debug page exposed                                                      | medium   | medium     | browser, api | 489     |
| [`disclosure.private-ip`](docs/rules/disclosure.private-ip.md) — Private IP address disclosed                                            | low      | medium     | browser, api | 200     |
| [`disclosure.directory-listing`](docs/rules/disclosure.directory-listing.md) — Directory listing                                         | low      | high       | browser, api | 548     |
| [`disclosure.source-map`](docs/rules/disclosure.source-map.md) — Source map exposed                                                      | info     | high       | browser      | 540     |
| [`disclosure.server-error`](docs/rules/disclosure.server-error.md) — Server error during tests                                           | info     | high       | browser, api | 755     |
| [`browser.csp-violation`](docs/rules/browser.csp-violation.md) — CSP violation in the browser                                            | info     | high       | browser      | 693     |
| [`asset.sri-missing`](docs/rules/asset.sri-missing.md) — Third-party script or style without SRI                                         | low      | high       | browser      | 353     |
| [`browser.open-redirect-candidate`](docs/rules/browser.open-redirect-candidate.md) — Open redirect candidate                             | medium   | medium     | browser, api | 601     |
| [`browser.reflected-param`](docs/rules/browser.reflected-param.md) — Query parameter reflected in HTML                                   | info     | low        | browser      | 79      |

<!-- rules:end -->

Every rule page explains why it matters, how to fix it (nginx, Express, Spring) and its known
false positives.

## Reports

All in `reports/pw-sec/`, written also when tests fail:

- `report.html` — one offline file: outcome, filters, details with evidence and a ready baseline
  entry, coverage, and what the scan does not cover.
- `report.json` — everything, for your own tooling.
- `results.sarif` — SARIF 2.1.0; findings point to the test that first saw them.
- `junit.xml` — one suite per rule group; new blocking findings are failures.
- `outcome.json` — the result code.

Evidence is redacted before it leaves the browser worker: cookie values, tokens, JWTs, secrets and
`Authorization` headers never reach any file; response bodies never leave the worker.

## CI

### GitHub Actions (SARIF in the Security tab)

```yaml
- run: npx playwright test
  env:
    PW_SEC_MODE: scan
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: reports/pw-sec/results.sarif
    category: playwright-security-scan
- uses: actions/upload-artifact@v4
  if: always()
  with:
    name: pw-sec
    path: reports/pw-sec/
```

### GitLab CI

```yaml
security-scan:
  script:
    - PW_SEC_MODE=scan npx playwright test
  artifacts:
    when: always
    paths: [reports/pw-sec/]
    reports:
      junit: reports/pw-sec/junit.xml
```

### Azure DevOps

```yaml
- script: npx playwright test
  env:
    PW_SEC_MODE: scan
- task: PublishTestResults@2
  condition: always()
  inputs:
    testResultsFormat: JUnit
    testResultsFiles: reports/pw-sec/junit.xml
    testRunTitle: pw-sec
```

## With playwright-performance-regression

Both packages can be used in one project. Wrap the config with `withSecurity()` **outside**
`withPerf()` (in perf mode `withPerf()` keeps only the reporters it knows); the fixtures can be
chained in any order:

```ts
export default withSecurity(withPerf(defineConfig({/* … */})));
export const test = withSecurityFixtures(withPerfFixtures(base));
```

In the reverse order (`withPerf(withSecurity(...))`) perf mode removes the security reporter:
nothing is scanned and the run still passes. Check that the console shows the `pw-sec · mode: …` header
after the first run.

Run the two scans in separate CI jobs: body analysis adds load that can distort step timings.

## Limitations

- Chromium is the supported browser; Firefox and WebKit work on a best-effort basis.
- Responses mocked with `route.fulfill()` are skipped.
- `transport.weak-tls` needs a server offering TLS 1.0/1.1, which current browsers refuse anyway.
- On `localhost`, transport rules (HSTS, `Secure` cookies, cleartext) are reported with low
  confidence and do not fail the scan.

## Privacy

The package sends nothing anywhere: no telemetry, no network calls of its own, and the HTML report
loads nothing from the network.

## License

MIT
