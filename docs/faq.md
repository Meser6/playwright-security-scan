# FAQ

## Does the package change my normal test runs?

No. Without `PW_SEC_MODE`, `withSecurity()` returns your config object itself and the fixtures add
only a `security` fixture that does nothing: no listener, no script, no reporter, no files.

## Does it send requests or attack my application?

No. The scan is passive: it reads the traffic your tests produce and never sends a request of its
own or changes one. It cannot find issues that need an attack (injection, broken access control);
active checks are planned for later versions. It does not replace a penetration test.

## Is a green scan a proof that the application is secure?

No. A green scan means "nothing new at or above the gate since the last accepted baseline, on the
pages and endpoints the tests visited". Endpoints no test calls are not checked; the report shows
the coverage.

## Where do false alarms come from?

From heuristics: a cookie name that looks like a session cookie, a JSON field named `password`, a
value that looks like a secret. Each [rule page](rules/README.md) lists its known false positives
and the option that narrows it. Mark a false alarm as `"status": "false-positive"` in the baseline:
it never expires, and the entry stays even when the finding is gone.

## A finding is in the baseline but the scan still fails

- The entry expired: its `until` date has passed (code 2). Fix the issue, extend `until` or remove
  it.
- The fingerprint changed: the subject is part of it, so a renamed cookie, a moved origin or a new
  endpoint key is a new finding. Run `baseline` again and remove the old entry if it is not
  resolved automatically.

## Several environments

The package has one baseline file per configuration (`baseline.path`); there is no environment
setting. Most teams scan one test environment. When the same tests really run against several
environments whose headers or cookies differ, pick the file from your own variable in
`pw-sec.config.ts`:

```ts
import { defineSecurityConfig } from 'playwright-security-scan/config';

export default defineSecurityConfig({
  baseline: { path: `security-baseline.${process.env.TEST_ENV ?? 'qa'}.json` },
});
```

Run `baseline` and `scan` once per environment with `TEST_ENV` set, and commit each file. For SARIF
in GitHub code scanning give each upload its own `category` (`category: pw-sec-${{ matrix.env }}`
in `github/codeql-action/upload-sarif`), so one environment does not close the alerts of another.

## The scan says NO_TRAFFIC

No response was in scope. Run a [check](cli.md#dry-run-check): it shows which origins are in scope
and where the traffic actually went. Usually `use.baseURL` is missing, the API is on another origin
(`scope.origins`), or the tests import `test` from `@playwright/test` instead of the wrapped one.

## Why is my localhost finding not blocking?

On `localhost`, `127.0.0.1` and `[::1]` the transport rules (HSTS, `Secure` cookies, cleartext HTTP)
are reported with low confidence: a local server rarely has TLS, and the real server may.

## Can I scan Firefox or WebKit?

Yes, the projects of your test command are scanned in every browser. Chromium is the reference:
the TLS version and some security details are reported differently by other engines, so a finding
may appear in one browser only. Scanning one engine is enough for most apps.

## Are API tests scanned?

Yes: every call of the `request` fixture (and of contexts registered with `trackRequestContext()`)
is analysed with the rules that make sense without a browser (headers, cookies, CORS, tokens,
disclosure). A response seen from the browser and from an API test is one finding.

## Does it slow the tests down?

Somewhat: response bodies of HTML, JSON and scripts are read and analysed (up to 1 MB each, every
static asset once per worker). Run time is not the priority of a security job; keep it apart from
performance measurements.

## Where is my data sent?

Nowhere. No telemetry, no network calls, and the HTML report loads nothing from the network.
Evidence is redacted before it leaves the test worker; see
[Privacy of the evidence](reports.md#privacy-of-the-evidence).

## What are the limits?

- Responses mocked with `route.fulfill()` are skipped: they are not your server.
- WebSockets, Server-Sent Events and service worker traffic are not analysed.
- `transport.weak-tls` needs a server offering TLS 1.0 or 1.1, which current browsers refuse anyway.
- A response body is analysed up to `limits.maxBodyBytes` (1 MB by default).
- `test.only` cannot be detected, so a `baseline` run with it may remove entries it did not cover.
