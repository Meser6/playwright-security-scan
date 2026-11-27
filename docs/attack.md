# Attack mode (ZAP)

The attack mode is an optional deep active scan with [OWASP ZAP](https://www.zaproxy.org/), without
setting ZAP up. `PW_SEC_MODE=attack` runs your tests like `scan`; after the last test the package
starts ZAP in Docker, gives it the requests your tests made, runs the active scan within a budget,
maps the alerts to findings `zap.<pluginId>` and stops ZAP. The findings go through the same
baseline and gate as every other finding.

The active scan **sends attacks** (XSS, SQL injection and many more payloads) to your application.
Run it only against an environment your team owns and may attack, never on production and never on
pull requests: a nightly job is the right place ([CI recipe](ci.md#nightly-attack-run)).

## Requirements

- **Docker** (GitHub's `ubuntu-latest` runners have it). Without Docker the run ends with
  `ATTACK_DOCKER_MISSING` (code 3); the passive scan is reported anyway.
- **Linux for an app on localhost.** On Linux the container uses `--network host` and reaches the
  app the job started on `localhost`. On macOS and Windows a container cannot reach the localhost of
  the machine, so a local origin stops the run (`ATTACK_LOCAL_ORIGIN_UNSUPPORTED`); start ZAP
  yourself and set `attack.zapUrl`, or run the attack in CI on Linux.
- About 1 GB of memory for ZAP. Pull the image in a step before the tests:
  `docker pull zaproxy/zap-stable`.

## Turn it on

```ts
// pw-sec.config.ts
import { defineSecurityConfig } from 'playwright-security-scan/config';

export default defineSecurityConfig({
  attack: {
    // Required, no default: the only origins ZAP may attack (the app the CI job started).
    allowedOrigins: ['http://localhost:3000'],
  },
});
```

```sh
PW_SEC_MODE=attack npx playwright test           # scan + ZAP, the gate on
PW_SEC_MODE=attack-baseline npx playwright test  # baseline + ZAP: zap.* findings go to the baseline
```

The `attack.*` options are read only in these two modes; `scan`, `baseline` and `check` ignore them
and never start ZAP. The authorization tests (`authz.enabled`) run in the attack modes too.

## Safety

- **Only allowed origins.** `attack.allowedOrigins` has no default; without it the run stops before
  the tests (`ATTACK_ORIGINS_REQUIRED`). The ZAP context contains only these origins, the scan runs
  in scope only, and a request of the tests to any other origin is never given to ZAP.
- **Never production.** An allowed origin that starts with `www.`, has a `prod` or `production`
  part, or is a domain without a subdomain stops the run (`ATTACK_ORIGIN_DENIED`).
  `attack.denyOrigins` always wins.
- **Only requests your tests made.** ZAP gets them with its API (`sendRequest`, redirects not
  followed) and scans from there: no spider, no AJAX spider, no other URLs.
- **Reading methods by default.** `attack.methods` is `GET`, `HEAD`, `OPTIONS`. Adding `POST`,
  `PUT`, `PATCH` or `DELETE` attacks requests that change data and gives `ATTACK_MUTATING_METHODS`.
- **A budget.** At most `attack.maxRequests` requests (2000), `attack.maxRps` per second (10, one
  thread per host) and `attack.maxDurationMinutes` (30); then the scan is stopped
  (`ATTACK_BUDGET_EXCEEDED`). The budget is checked every 5 seconds.
- **Marked.** Every request of ZAP carries `x-pw-sec-probe: <run id>` (`attack.probeHeader: false`
  removes it).
- **Cleaned up.** The container `pw-sec-zap-<run id>` is stopped after the scan, after an error and
  on Ctrl+C. ZAP runs with `-silent`: no update checks, no telemetry.
- **No secrets on disk.** Templates have no cookies or credential headers; request bodies (only
  JSON, forms and plain text) have credential-like fields replaced by `[redacted]` and the same
  redaction as evidence (tokens, e-mails, card numbers). The session of the scan role and the API
  key of ZAP go to ZAP only and never into a file.

## The session ZAP uses

ZAP scans in one role: `attack.role`, or the first project with a `storageState` file (a role as in
[authorization tests](authz.md#roles)), or without a session when there is none. The package sends
the cookies of that `storageState` and the `authz.roles.<project>.headers` of the project with every
request of ZAP. Logout URLs (`logout`, `signout`, `sign-out`, `log-out`) are excluded from the scan,
so the session survives; add more paths with `attack.exclude`.

## Findings

Each alert of the active scan becomes a finding:

| Field       | From the alert                                                                       |
| ----------- | ------------------------------------------------------------------------------------ |
| rule        | `zap.<pluginId>`, e.g. `zap.40012` (Cross Site Scripting)                            |
| severity    | risk: High → high, Medium → medium, Low → low, Informational → info                  |
| confidence  | Confirmed/High → high, Medium → medium, Low → low; False Positive alerts are dropped |
| subject     | the endpoint key of the alert URL (same keys as every finding)                       |
| fingerprint | `zap.<pluginId>\|endpoint\|<endpoint key>\|<parameter>`                              |
| evidence    | the attack and the evidence of ZAP, redacted, up to 200 characters                   |
| docs        | name, description and solution of ZAP, and its alert page                            |

Alerts of ZAP's passive rules are not read: the passive scan is done by the rules of the package.
`rules: { 'zap.40012': 'off' }` drops an alert; `{ severity, confidence }` overrides its values.

A `zap.*` baseline entry is resolved only by an attack run whose scan completed within the budget
and covered its endpoint; in `scan` and `baseline` runs it is always "not covered" and never removed.

The HTML report has an **Attack** tab (ZAP version, role, requests, alerts, budget) and marks the
findings with a **ZAP** badge. SARIF uses the category `pw-sec-attack`, so the nightly alerts do not
replace the alerts of the pull-request scans; JUnit has a `zap` suite.

## Options

| Option                                  | Default                      | Meaning                                                      |
| --------------------------------------- | ---------------------------- | ------------------------------------------------------------ |
| `attack.allowedOrigins`                 | **none (required)**          | exact origins ZAP may attack                                 |
| `attack.denyOrigins`                    | `[]`                         | origins always refused                                       |
| `attack.iUnderstandThisIsNotProduction` | `false`                      | lifts the built-in production patterns (not `denyOrigins`)   |
| `attack.zapUrl`                         | none                         | a ZAP you started on this machine; no container then         |
| `attack.image`                          | `'zaproxy/zap-stable'`       | Docker image                                                 |
| `attack.role`                           | the first role               | the session of the scan, or `'anonymous'`                    |
| `attack.methods`                        | `['GET', 'HEAD', 'OPTIONS']` | methods of the requests given to ZAP                         |
| `attack.strength`                       | `'medium'`                   | attack strength of the scan policy (`low`, `medium`, `high`) |
| `attack.threshold`                      | `'medium'`                   | alert threshold of the scan policy                           |
| `attack.maxDurationMinutes`             | `30`                         | time budget                                                  |
| `attack.maxRequests`                    | `2000`                       | request budget                                               |
| `attack.maxRps`                         | `10`                         | requests per second                                          |
| `attack.exclude`                        | `[]`                         | endpoint key patterns left out (`*` within a segment)        |
| `attack.probeHeader`                    | `true`                       | the `x-pw-sec-probe` header                                  |

With `attack.zapUrl` the API key comes from `PW_SEC_ZAP_API_KEY` (never from the config); the
package removes its context, rules and scan policy from that ZAP after the scan. Without
`attack.zapUrl` it makes a random key per run. The attack mode does not run in shards
(`ATTACK_SHARDED`).
