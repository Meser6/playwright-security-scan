# Reports

A `scan` or `baseline` run writes its reports to `reports/pw-sec/` (`report.dir`), also when tests
fail or the tool fails. A [check](cli.md#dry-run-check) writes nothing. Add the directory to
`.gitignore`.

| File            | For                                                                       | Option                             |
| --------------- | ------------------------------------------------------------------------- | ---------------------------------- |
| `report.html`   | people: one offline file with filters, details and ready baseline entries | `report.html`                      |
| `report.json`   | your own tooling: everything the run knows                                | `report.json`                      |
| `results.sarif` | GitHub code scanning and other security dashboards (SARIF 2.1.0)          | `report.sarif`                     |
| `junit.xml`     | any CI test view (GitLab, Azure DevOps, Jenkins, …)                       | `report.junit`, `report.junitPath` |
| `outcome.json`  | CI scripts: the result code, apart from the functional tests              | always                             |

## Console

See [Console output](cli.md#console-output) and [Colors](cli.md#colors).

## HTML report

One self-contained file that loads nothing from the network (its Content-Security-Policy allows
only its own script and styles), in the same look as the report of
[playwright-performance-regression](https://github.com/Meser6/playwright-performance-regression),
in a light and a dark theme:

- the verdict as in the console, with the exit code, and six counters (new blocking, new
  non-blocking, accepted, expired, resolved, not covered); a counter above zero opens the
  filtered list;
- **Findings**: new blocking findings first, then expired, new non-blocking and baseline entries;
  filters for classification, severity, confidence, rule group and origin, a search over rule,
  subject and test, and sorting by any column (sort by Rule or Subject to group the findings). A
  click on a row opens the details in a dialog (Previous / Next finding, `Esc` closes it): the state against the baseline (note, added, until, "expires
  in N days"), the fingerprint, where it is, the redacted evidence, the tests that saw it (the
  first one with its step), why it matters, how to fix it, known false positives, CWE and OWASP,
  and for a new or expired finding the baseline entry to paste;
- **Coverage**: responses in and out of scope, origins, endpoints, tests without traffic, rules
  that had nothing to check, resolved and not covered baseline entries, and what the scan does
  not cover;
- **Run & config**: the run, the enabled rules with their preset, the resolved configuration and
  the diagnostics.

Without JavaScript the page shows every tab one below the other, and each finding's details open
from its row. Links: `report.html#tab=coverage` opens a tab, and
`report.html#finding=<fingerprint>` (the **Copy link** button of the dialog, with the fingerprint
URL-encoded) opens a finding; the fingerprint does not change between runs, so the link works in
the next report too. 1000 findings open in under two
seconds.

## JSON

`report.json` follows `schemas/run-report.schema.json` of the package (`schemaVersion` 2): mode,
scope, coverage (responses per origin and endpoint, traffic outside the scope, bodies analysed and
skipped, rules run), every finding with its classification and baseline entry, resolved and not
covered entries, tests without traffic, diagnostics and the outcome.

`outcome.json` (`schemas/outcome.schema.json`):

```json
{
  "schemaVersion": 2,
  "code": 1,
  "name": "NEW_FINDINGS",
  "testsPassed": true,
  "newBlocking": 2,
  "newNonBlocking": 5,
  "expired": 0,
  "resolved": 1
}
```

## SARIF

`results.sarif` has one run with the enabled rules (help text, CWE and OWASP tags,
`security-severity`, a link to the [rule page](rules/README.md)) and the `new` and `expired`
findings (`report.sarifIncludeAccepted: true` adds baseline entries as suppressed results with the
note as justification). A scanner of the traffic knows no line of your application code, so each
result points to the **test** that first saw it; its fingerprint keeps GitHub from duplicating
alerts when the test moves. The category is `pw-sec` (`automationDetails.id` is
`pw-sec/<runId>`); for several environments set `category` in the upload step, see
[Several environments](faq.md#several-environments).

## JUnit XML

One `<testsuites name="pw-sec">`, one suite per rule group and one test case per finding:

| Finding                           | Test case                                                 |
| --------------------------------- | --------------------------------------------------------- |
| new, blocking                     | failure, with evidence, tests, fix and the baseline entry |
| expired                           | failure `baseline-expired`                                |
| new, non-blocking                 | passed, with the description                              |
| accepted, wontfix, false-positive | skipped (`report.junitIncludeAccepted`)                   |

Without findings the file has one passed `no findings` case, so CI does not complain about missing
results; a tool error adds a `pw-sec` case with an error. The file is separate from the JUnit
report of your functional tests.

## Privacy of the evidence

Response bodies never leave the test worker. Before a finding leaves the worker its evidence is
redacted: cookie values, tokens, JWTs, `Authorization` headers and secrets become
`[redacted sha256:…]` with a salted hash that is the same within one run, so you can still tell two
values apart. No file of the package contains them. The package sends nothing anywhere: no
telemetry and no network calls of its own.
