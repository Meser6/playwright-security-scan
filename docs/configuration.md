# Configuration

Everything is optional: without a config the scope is the origin of `use.baseURL` of each project
and the `recommended` rules run with the gate at `medium`.

Pass the config as the second argument of `withSecurity()`:

```ts
// playwright.config.ts
import { defineConfig } from '@playwright/test';
import { withSecurity } from 'playwright-security-scan/config';
import security from './pw-sec.config';

export default withSecurity(defineConfig({/* … */}), security);
```

```ts
// pw-sec.config.ts
import { defineSecurityConfig } from 'playwright-security-scan/config';

export default defineSecurityConfig({
  scope: {
    origins: ['https://api.example.com'],
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

or point `PW_SEC_CONFIG` to a file (a `.json` file or a module with a default export); the file
wins over the argument, which is handy for a CI-only config.

The config is checked when `withSecurity()` runs, before any test: an unknown option or rule id
fails with the closest valid name, a wrong type or value with the allowed ones, and all problems
are listed at once ([`CONFIG_*` codes](troubleshooting.md#mode-and-config)).

## Scope

| Option                 | Type                | Default | Meaning                                                                                                 |
| ---------------------- | ------------------- | ------- | ------------------------------------------------------------------------------------------------------- |
| `scope.origins`        | `string[]`          | `[]`    | Origins scanned besides the `use.baseURL` origins; `*` allowed in a subdomain (`https://*.example.com`) |
| `scope.includeBaseURL` | `boolean`           | `true`  | Scan the origin of `use.baseURL` of every scanned project                                               |
| `scope.exclude`        | `string[]`          | `[]`    | Origins never scanned, even when they match                                                             |
| `scope.projects`       | `string[] \| 'all'` | `'all'` | Playwright projects whose tests are scanned (e.g. without `setup`)                                      |
| `scope.api`            | `boolean`           | `true`  | Scan the calls of `APIRequestContext` (the `request` fixture)                                           |

Traffic outside the scope is counted, never analysed. The [check](cli.md#dry-run-check) lists it,
so you can see which origin to add. Analytics, fonts and CDNs are not your app: leave them out.

## Rules

| Option          | Type                                                    | Default         | Meaning                                                                             |
| --------------- | ------------------------------------------------------- | --------------- | ----------------------------------------------------------------------------------- |
| `rules.preset`  | `'recommended' \| 'strict' \| 'minimal'`                | `'recommended'` | The set of rules and their severities                                               |
| `rules['<id>']` | `'off' \| 'on' \| { severity?, confidence?, options? }` | from the preset | Turn a rule off or on, change its severity, confidence or options                   |
| `rules.custom`  | `Rule[]` (from `defineRule()`)                          | `[]`            | Your own rules, ids `custom.<name>` ([Custom rules](custom-rules.md), experimental) |

- `recommended`: every rule except two strict-only header rules.
- `strict`: every rule; `info` becomes `low`, and `low` with high confidence becomes `medium`.
- `minimal`: only rules with high confidence.

Rule options (for example the token parameter names of `data.token-in-url` or the names of
non-session cookies) are listed on each [rule page](rules/README.md). An unknown option or a value
of another type than the default fails the config check.

Custom rules (`rules.custom`) take presets and `rules['custom.<name>']` settings like built-in rules.
They need a TypeScript or JavaScript config: a JSON file in `PW_SEC_CONFIG` cannot hold them. See
[Custom rules](custom-rules.md).

## Gate

| Option                 | Type         | Default    | Meaning                                                    |
| ---------------------- | ------------ | ---------- | ---------------------------------------------------------- |
| `gate.minSeverity`     | `Severity`   | `'medium'` | The lowest severity of a new finding that fails the scan   |
| `gate.minConfidence`   | `Confidence` | `'medium'` | The lowest confidence of a new finding that fails the scan |
| `gate.failOnExpired`   | `boolean`    | `true`     | An expired baseline entry fails the scan (code 2)          |
| `gate.failOnNoTraffic` | `boolean`    | `true`     | No response in scope fails the run (code 4)                |

Severities: `info`, `low`, `medium`, `high`, `critical`. Confidences: `low`, `medium`, `high`. New
findings below the gate are reported as non-blocking.

## Baseline

| Option                   | Type      | Default                    | Meaning                                                              |
| ------------------------ | --------- | -------------------------- | -------------------------------------------------------------------- |
| `baseline.path`          | `string`  | `'security-baseline.json'` | The baseline file, relative to the Playwright config                 |
| `baseline.pruneResolved` | `boolean` | `true`                     | A `baseline` run removes entries whose finding is gone               |
| `baseline.requireNote`   | `boolean` | `false`                    | Accepted and `wontfix` entries must have a `note` (code 3 otherwise) |

See [The baseline](baseline.md).

## Limits and browser

| Option                      | Type       | Default                   | Meaning                                                          |
| --------------------------- | ---------- | ------------------------- | ---------------------------------------------------------------- |
| `limits.maxBodyBytes`       | `number`   | `1048576`                 | Longer bodies are cut before analysis                            |
| `limits.bodyContentTypes`   | `string[]` | HTML, JSON, JS, text, XML | Content types whose bodies are read (`*+json` allowed)           |
| `limits.maxFindingsPerRule` | `number`   | `200`                     | Findings of one rule per test; more give `RULE_FINDINGS_LIMIT`   |
| `browser.cspEvents`         | `boolean`  | `true`                    | Listen to CSP violations in the page                             |
| `browser.storageScan`       | `boolean`  | `true`                    | Look at `localStorage` and `sessionStorage` at the end of a test |

## Reports

| Option                                     | Type      | Default                  | Meaning                                             |
| ------------------------------------------ | --------- | ------------------------ | --------------------------------------------------- |
| `report.dir`                               | `string`  | `'reports/pw-sec'`       | Where reports go, relative to the Playwright config |
| `report.html` / `json` / `sarif` / `junit` | `boolean` | `true`                   | Which reports to write                              |
| `report.junitPath`                         | `string`  | `<report.dir>/junit.xml` | For CI artifact patterns                            |
| `report.junitIncludeAccepted`              | `boolean` | `true`                   | Baseline entries in JUnit, as skipped tests         |
| `report.sarifIncludeAccepted`              | `boolean` | `false`                  | Baseline entries in SARIF, as suppressed results    |

See [Reports](reports.md).

## Endpoint keys

`normalization` decides how URLs become endpoint keys such as `GET /api/items/:id`. It is the same
as the `keys` section of `playwright-performance-regression`, so both packages name endpoints the
same way:

| Option                          | Default   | Meaning                                                                                           |
| ------------------------------- | --------- | ------------------------------------------------------------------------------------------------- |
| `normalization.idPatterns`      | all on    | Which path segments become `:id` (`number`, `uuid`, `hex`, `token`, `mixed`, `prefixed`, `email`) |
| `normalization.extraIdPatterns` | `[]`      | More patterns (strings, `RegExp` or `{ regex, flags }`)                                           |
| `normalization.query`           | `'names'` | `'names'` keeps the query parameter names, `'ignore'` drops the query                             |
| `normalization.keepQueryValues` | `[]`      | Parameters whose values stay in the key                                                           |
| `normalization.dropQueryParams` | `[]`      | Parameters left out of the key                                                                    |
| `normalization.origins`         | `{}`      | Origin → label, for shorter keys                                                                  |
| `normalization.keyBuilder`      | none      | Your own function; its result is checked                                                          |

Endpoint keys group findings of API rules and appear in the reports; they never contain values.

## Authorization tests

`authz.*` options switch on the GET/HEAD replays of [Authorization tests](authz.md) (off by
default; `authz.allowedOrigins` is required when `authz.enabled` is `true`). Their findings take
`rules['authz.<test>']` settings like rules; presets do not change them.

## Attack mode

`attack.*` options configure the ZAP active scan of `PW_SEC_MODE=attack` and `attack-baseline`
([Attack mode](attack.md)); other modes ignore them. `attack.allowedOrigins` is required in these
modes and has no default. `rules['zap.<pluginId>']` takes `'off'` or `{ severity, confidence }`.

## Contexts created by hand

The fixtures scan the `context`, `page` and `request` fixtures. Other contexts need one line:

| Context                              | Call                                                                   |
| ------------------------------------ | ---------------------------------------------------------------------- |
| `browser.newContext()` inside a test | `await security.track(context)` (the `security` fixture)               |
| a worker-scoped browser context      | `await trackContext(context)` from `playwright-security-scan/fixture`  |
| `playwright.request.newContext()`    | `trackRequestContext(context)` from `playwright-security-scan/fixture` |

All of them do nothing outside a scan.
