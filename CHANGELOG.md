# Changelog

All notable changes to this project are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- A cookie whose name looks like a session (`session-username`, `auth`) but whose value is plain words (`standard_user`, `true`) is no longer taken for a session cookie (false positive of `cookie.no-httponly` and `cookie.no-secure` on SauceDemo).
- A baseline run no longer reports its new findings as warnings in the verdict: they were just written to the baseline.

### Added

- `docs/init.md` describes the guided setup; the README starts with `npm init playwright-security-scan`.
- `npx pw-sec` and the new `create-playwright-security-scan` package (`npm init playwright-security-scan`): the start of the guided setup — installation, the tutorial question, 7 languages (`PW_SEC_LANG`), `PW_SEC_DRY_RUN`, `PW_SEC_NO_TUTORIAL`, what the package does and how to run it, and checks for a missing `playwright.config` or an old Playwright. Then the questions (rule preset, gate, origins of your app with suggestions from your sources, environments, test command) and the changes, each shown as a diff before it is written: a short `pw-sec.config.*` (TypeScript, ESM or CommonJS), `withSecurity()` in `playwright.config` (outside `withPerf()`, also fixing the reverse order), `withSecurityFixtures()` in your fixtures module or the `playwright-security-scan/test` import in test files, and `reports/pw-sec/` in `.gitignore`. A second run changes nothing. At the end the wizard offers a check — your test command runs with `PW_SEC_MODE=check`, then `baseline` and `scan` with the baseline in a temporary folder — and explains a failure (no traffic in scope, a tool error, unstable traffic); it ends with an IMPORTANT box with the exact commands for your project (per environment label, `cross-env` on Windows).
- Documentation like the perf package: `docs/cli.md`, `docs/configuration.md`, `docs/baseline.md`, `docs/reports.md`, `docs/ci.md` (GitHub Actions, GitLab, Azure DevOps, Jenkins, environments, schedule), `docs/adoption.md`, `docs/faq.md` and `docs/upgrading.md`; the README is now a short introduction with links, and the rules table lives in `docs/rules/README.md`.
- `playwright-security-scan/test`: a ready `test` and `expect` for specs that import them from `@playwright/test`, so set-up needs no fixture module (one import change per spec file).
- Dry run: `PW_SEC_MODE=check` runs the first test of each file (at most `PW_SEC_MAX_TESTS`, default 10) and prints the origins in scope with their responses, the traffic outside the scope, the scanned projects, the rules, the baseline state, how many findings would be new and a `READY` / `NOT READY` verdict. Nothing is written. `report.json` coverage now lists the origins outside the scope (`outOfScopeOrigins`).
- One baseline per environment: `PW_SEC_ENV=qa` (or `run.env` in the config) uses `security-baseline.qa.json`. The label is checked before the run (`ENV_INVALID`), never falls back to the file without a label (`BASELINE_ENV_MISSING`), is written to the baseline file (`BASELINE_ENV_MISMATCH` when it differs) and appears in the console, `report.json`, `outcome.json` (`env`), the HTML report, SARIF (category `pw-sec/<env>`) and JUnit.

### Changed

- The console output looks like the one of `playwright-performance-regression`: colors in a terminal (`NO_COLOR`, `FORCE_COLOR` and `TERM=dumb` are respected), the start banner as a table, errors and warnings in framed boxes, the counters and the blocking findings in tables, the verdict in a box (`✅ PASSED`, `⚠ PASSED WITH WARNINGS`, `❌ FAILED`, `❌ ERROR`) with the result name and code, and one `Report:` line with the absolute path of the HTML report. The text is the same without colors and still fits in 30 lines.

## [0.1.0-beta.0] - 2026-11-25

First test release, published under the `next` dist-tag (`npm i -D playwright-security-scan@next`).

### Fixed

- Google Analytics, consent and CDN cookies (e.g. `_ga_*`, `cf_clearance`) are no longer taken for session cookies; the session heuristic is configurable with `nonSessionNames`.
- `data.password-in-response` no longer reports labels such as `"password": "Password"` in translation files; the value must look like a password or a hash.
- `--reporter` on the command line removed the package reporter, so a scan could not fail; it now stops with `RUN_REPORTER_FLAG` and the flag to use.
- Responses whose body the page never read (e.g. `fetch` without `.json()`) were lost when the test ended before the body arrived; the collector now waits for them.

### Added

- Documentation: README (set-up, modes, baseline, configuration, rules table, reports, CI examples for GitHub Actions, GitLab and Azure DevOps, limits), one page per rule in `docs/rules/` and `docs/troubleshooting.md` with every code.
- HTML report (`reports/pw-sec/report.html`): one offline file with the outcome, filters (classification, severity, confidence, rule group, origin, test), grouping by rule, origin or endpoint, finding details with evidence, tests, why/fix/false positives and a ready baseline entry, the coverage of the run and the box "What this scan does not cover".
- SARIF 2.1.0 (`reports/pw-sec/results.sarif`) for GitHub code scanning and other security dashboards: every rule with help, CWE/OWASP tags and `security-severity`, findings located at the test that first saw them, stable fingerprints. JUnit XML (`reports/pw-sec/junit.xml`, `report.junitPath`) for GitLab, Azure DevOps, Jenkins and other CI: one suite per rule group, blocking findings as failures, baseline entries as skipped.
- The reporter: a start banner (mode, scope, rules, gate, baseline), findings deduplicated across the run and classified against `security-baseline.json` (new, accepted, wontfix, false-positive, expired; resolved and not covered entries), a summary of at most 30 lines, `reports/pw-sec/report.json` and `reports/pw-sec/outcome.json`, and the exit code: new findings above the gate (1), expired entries (2), tool errors (3) or no traffic in scope (4) fail the run. `PW_SEC_MODE=baseline` writes the baseline (sorted, notes and dates kept, resolved entries pruned except in filtered runs) and prints the diff.
- Rules for tokens and data (`data.*`: tokens in URLs, unsigned, endless, long-lived JWTs and JWTs with sensitive claims, passwords and hashes in responses), information disclosure (`disclosure.*`: stack traces, SQL errors, server versions, debug pages, private IP addresses, directory listings, source maps, server errors) and the browser (`browser.csp-violation`, `asset.sri-missing`, `browser.open-redirect-candidate`, `browser.reflected-param`). The catalog now has all 44 rules of the `recommended` preset (46 in `strict`).
- Rules for security headers (`header.*`: CSP missing/unsafe/incomplete/report-only, clickjacking, HSTS missing/weak, nosniff, Referrer-Policy, Content-Type; Permissions-Policy and COOP in the `strict` preset), cookies (`cookie.*`: Secure, HttpOnly, SameSite, long-lived sessions), CORS (`cors.*`) and transport (`transport.*`: cleartext, mixed content, forms over HTTP, outdated TLS). Each rule documents why it matters, how to fix it (nginx, Express, Spring) and known false positives.
- API tests are scanned too: calls of the `request` fixture, `page.request`, `context.request` and contexts registered with `trackRequestContext()` / `security.trackRequestContext()` become records of source `api`, analysed by the same rules where they apply. Wrapped methods return the original promise, value and error. Works together with `playwright-performance-regression` (use `withSecurity(withPerf(...))`).
- `withSecurityFixtures()`, `trackContext()` and the `security` fixture (`playwright-security-scan/fixture`): in scan mode the browser contexts of each test are scanned passively — responses in scope, CSP violation events, and the cookie jar and Web Storage at the end of the test — and the redacted findings are attached to the test result. Bodies are read with limits, static assets once per worker. Without `PW_SEC_MODE` only an inactive `security` fixture is added.
- First rules: `header.xcto-missing`, `data.secret-in-asset`, `data.token-in-storage`.
- `withSecurity()` and `defineSecurityConfig()` (`playwright-security-scan/config`): `PW_SEC_MODE=scan|baseline` turns the scan on, the package reporter is appended, and the package config is validated with suggestions for mistyped options and rule ids. Without `PW_SEC_MODE` the Playwright config is returned unchanged. `PW_SEC_CONFIG` points to another config file.
- Rule presets `recommended` (default), `strict` and `minimal`.
- JSON Schemas of the file formats (`schemas/`, exported as `playwright-security-scan/schemas/*`): test attachment, baseline file, run report and outcome file.

[Unreleased]: https://github.com/Meser6/playwright-security-scan/compare/v0.1.0-beta.0...HEAD
[0.1.0-beta.0]: https://github.com/Meser6/playwright-security-scan/releases/tag/v0.1.0-beta.0
