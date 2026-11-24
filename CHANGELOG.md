# Changelog

All notable changes to this project are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

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
