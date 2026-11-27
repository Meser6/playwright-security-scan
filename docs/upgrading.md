# Upgrading

The package follows [Semantic Versioning](https://semver.org/). Before 1.0.0 a minor version may
change the console output, report fields or rule details; the [changelog](../CHANGELOG.md) lists
every user-visible change. Fingerprints, and so your baseline file, are kept stable: when a change
would alter them, it is listed here with the way to migrate.

## Upgrading

1. Update the package: `npm install --save-dev playwright-security-scan@<version>` (`@next` for
   pre-releases).
2. Read the changelog entries between your version and the new one.
3. Run a [check](cli.md#dry-run-check), then a `scan`. New rules or changed severities can add
   findings: review them like any new finding and accept them with a `baseline` run if needed.

### From 0.2.0-beta.0

- Environment labels are removed: `PW_SEC_ENV` is ignored with the warning
  [`ENV_REMOVED`](troubleshooting.md#env_removed), and `run.env` in the config is an unknown option
  ([`CONFIG_UNKNOWN_OPTION`](troubleshooting.md#config_unknown_option)): delete it. Every run uses
  `baseline.path` (`security-baseline.json` by default). If you used a label, rename your
  `security-baseline.<env>.json` to `security-baseline.json`, or set `baseline.path` per
  environment as in [Several environments](faq.md#several-environments). An `"env"` field left in
  a baseline file is ignored and dropped by the next `baseline` run.
- `report.json` and `outcome.json` have `schemaVersion: 2`, without the `env` field. The SARIF
  category is always `pw-sec` (`automationDetails.id` is `pw-sec/<runId>`) and the JUnit root is
  always `<testsuites name="pw-sec">`.
- The guided setup has eight steps (no environment question) and its check is one trial run.

### From 0.1.0-beta.0

- The console output is new (colors, boxes, tables, a verdict box). Scripts that parsed the old
  last line `pw-sec: NAME (code N)` should read `reports/pw-sec/outcome.json` instead.
- `report.json` and `outcome.json` have a new `env` field (`null` without an environment label),
  and the coverage has `outOfScopeOrigins`.
- New: environment labels (`PW_SEC_ENV`, removed again after 0.2), the
  [check](cli.md#dry-run-check) (`PW_SEC_MODE=check`) and `playwright-security-scan/test`. The
  baseline file format is unchanged.

## Uninstalling

1. Remove `withSecurity()` from the Playwright config and `withSecurityFixtures()` from your
   fixture module (or switch the `playwright-security-scan/test` imports back to
   `@playwright/test`).
2. Remove `security.track()`, `trackContext()` and `trackRequestContext()` calls, if any.
3. Delete `security-baseline*.json`, `pw-sec.config.*`, `reports/pw-sec/` and the CI job.
4. `npm uninstall playwright-security-scan`.
