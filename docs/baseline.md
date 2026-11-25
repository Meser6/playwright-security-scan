# The baseline

`security-baseline.json` is the list of findings you have decided about. It lives next to the
Playwright config (`baseline.path`) and is committed like code. A `scan` run fails only on findings
that are **not** in it, so you can adopt the package on an application with known issues and still
catch every new one.

## The file

```json
{
  "schemaVersion": 1,
  "generatedBy": "playwright-security-scan@0.1.0",
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

- The key is the **fingerprint** of the finding: rule, kind of subject, subject and, for some
  rules, a detail (for example the unsafe CSP keyword). It is stable between runs: the same issue
  on the same origin, cookie or endpoint key always has the same fingerprint, whichever test or
  browser saw it, and whether it came from the browser or an API test.
- `status`: `accepted` (risk accepted), `wontfix` (deliberately not fixed; give a `note`) or
  `false-positive` (not a problem; never expires).
- `note` (optional): why. With `baseline.requireNote: true` every `accepted` and `wontfix` entry
  needs one, or the scan ends with [`BASELINE_NOTE_REQUIRED`](troubleshooting.md#baseline_note_required).
- `until` (optional, `YYYY-MM-DD`): after this date the entry no longer protects the finding.
- `severity` is informational and follows the current rule severity.
- The file holds no evidence, no URLs with values, no test names and no counters, so its diffs show
  only real decisions. Entries are sorted by fingerprint, one per key.

The JSON schema is `node_modules/playwright-security-scan/schemas/baseline.schema.json`.

## Workflow

```sh
# 1. Accept the current state
PW_SEC_MODE=baseline npx playwright test

# 2. Review the diff in the console, security-baseline.json and reports/pw-sec/report.html.
#    Fix what is cheap to fix, add a "note" (and an "until" date) to what you accept,
#    change the status of false positives to "false-positive".

# 3. Commit
git add security-baseline.json && git commit -m "Accept the current security findings"

# 4. In CI and locally: fail only on new findings
PW_SEC_MODE=scan npx playwright test
```

A `baseline` run prints the diff of the file:

```
security-baseline.json
  + cookie.no-httponly | session_id@app.example.com   medium
  - disclosure.stack-trace | POST /api/orders   (resolved)
  = 9 unchanged
Review the new entries, add a "note" (and optionally "until"), then commit.
```

It adds every current finding that is not in the file as `accepted` with today's `addedAt` and no
`note`, keeps `status`, `note`, `until` and `addedAt` of existing entries, updates their
`severity`, and removes resolved entries (below). New findings never fail a `baseline` run; tool
errors and no traffic still do.

The HTML report shows, for each new finding, the entry to paste into the file.

## How findings are classified

| Classification   | When                                                       | Fails the scan                                                        |
| ---------------- | ---------------------------------------------------------- | --------------------------------------------------------------------- |
| `new`            | the fingerprint is not in the file                         | when at or above `gate.minSeverity` and `gate.minConfidence` (code 1) |
| `accepted`       | an `accepted` entry without `until`, or `until` not passed | no                                                                    |
| `wontfix`        | a `wontfix` entry without `until`, or `until` not passed   | no                                                                    |
| `false-positive` | a `false-positive` entry                                   | no                                                                    |
| `expired`        | an `accepted` or `wontfix` entry whose `until` has passed  | with `gate.failOnExpired` (code 2)                                    |

New findings below the gate are reported as non-blocking. With several causes the result is the
first of `TOOL_ERROR`, `NEW_FINDINGS`, `BASELINE_EXPIRED`, `NO_TRAFFIC`, `OK`.

## Expiry

Fourteen days before `until` the console and the report warn that the entry expires; the verdict
becomes `PASSED WITH WARNINGS`. After the date (the run date in UTC) the entry is `expired`: the
finding is blocking again until you fix it, extend `until` or remove the date.
`false-positive` entries never expire; an `until` on one gives
[`BASELINE_STALE_STATUS`](troubleshooting.md#baseline_stale_status).

## Resolved and not covered entries

An entry whose finding did not occur in the run is **resolved** only when the run covered its
subject: a document of the origin was loaded, the endpoint key was called, the origin that sets the
cookie responded, the asset was loaded, or the storage of the origin was scanned. Otherwise the
entry is **not covered**: the tests did not go there, so the package cannot tell.

- A `scan` run only reports resolved entries (`→ 1 baseline entry resolved — run baseline mode to
remove it`); it never changes the file.
- A `baseline` run removes resolved entries (`baseline.pruneResolved`, on by default), except
  `false-positive` entries, which describe a rule, not your app. Not covered entries stay.

## Partial runs

A `baseline` run that sees only part of the tests could take an entry for resolved when the tests
that cover it did not run. So when the command filters the tests (`--grep`, `--grep-invert`,
`--project`, `--shard`, file or line arguments, `--only-changed`, `--last-failed`), resolved
entries are kept and the run warns with [`PARTIAL_RUN`](troubleshooting.md#partial_run). New
findings are still added.

`test.only` cannot be detected: avoid it in a `baseline` run.

## Merge conflicts

Two branches that accept different findings both add entries to the file. With one entry per
fingerprint, sorted, the conflict is usually two neighbouring blocks: keep both sides, then run
`PW_SEC_MODE=baseline` again to rewrite the file in order.

## One baseline per environment

Headers, cookies and origins often differ between environments (a staging proxy, a production
CDN), so one baseline for all of them mixes accepted risks. Give each environment its own file with
an environment label:

```sh
PW_SEC_MODE=baseline PW_SEC_ENV=qa npx playwright test   # writes security-baseline.qa.json
PW_SEC_MODE=scan PW_SEC_ENV=qa npx playwright test       # reads security-baseline.qa.json
```

`run.env` in the config sets a default label; `PW_SEC_ENV` overrides it. A label is 1 to 32
lowercase letters, digits and `-`, starting with a letter or a digit; anything else stops the run
before the tests ([`ENV_INVALID`](troubleshooting.md#env_invalid)).

- A labelled run uses only its own file and never falls back to the file without a label. When
  only that one exists, the run warns with
  [`BASELINE_ENV_MISSING`](troubleshooting.md#baseline_env_missing): run `baseline` with the label,
  or copy the file.
- A `baseline` run writes the label into the file (`"env": "qa"`). A file used by a run with
  another label warns with [`BASELINE_ENV_MISMATCH`](troubleshooting.md#baseline_env_mismatch).
- The label is shown in the console and written to every report; in SARIF it is part of the
  category, so GitHub code scanning keeps the alerts of each environment apart.

## Invalid file

Unreadable JSON, a wrong `schemaVersion` or an entry with an unknown rule id end the scan with
[`BASELINE_INVALID`](troubleshooting.md#baseline_invalid) (code 3) and the exact place of the
problem; a `baseline` run does not overwrite an invalid file. An entry of a rule turned off in the
config is ignored ([`BASELINE_RULE_OFF`](troubleshooting.md#baseline_rule_off)).
