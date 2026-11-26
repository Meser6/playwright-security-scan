# Troubleshooting

Every problem the package reports has a code in capital letters, such as `NO_TRAFFIC`. This page
has one section per code: what it means and how to fix it. Search the page for the code you see.

## Where codes appear

- **Playwright output** at start-up: an invalid mode or package config stops Playwright before any
  test runs, with a list of `MODE_*` and `CONFIG_*` problems and the closest valid names.
- **Console summary** at the end of a scan: the result line `✔|✘ pw-sec: <NAME> (code N)` and up
  to three warnings or errors.
- **`reports/pw-sec/report.json`** (`diagnostics`) and **`report.html`** (section Diagnostics):
  every diagnostic of the run with its level.
- **`reports/pw-sec/outcome.json`**: the result code for CI.

Levels: **error** makes the result untrustworthy (code 3, `TOOL_ERROR`); **warn** is worth a look;
**info** is context only.

## Result codes

### OK

Code 0. No new finding at or above the gate (`gate.minSeverity`, `gate.minConfidence`).

### NEW_FINDINGS

Code 1. At least one finding that is not in `security-baseline.json` is at or above the gate. The
summary and the report list them with the test that first saw them. Fix the problem, or, after
review, accept it: run `PW_SEC_MODE=baseline`, add a `note` to the new entry and commit.

### BASELINE_EXPIRED

Code 2. A baseline entry has an `until` date in the past and the finding still occurs. Fix it, or
move `until` with a new note. `gate.failOnExpired: false` only reports it.

### TOOL_ERROR

Code 3. A diagnostic of level error made the result untrustworthy; it is listed in the summary and
the report. The sections below explain each one.

### NO_TRAFFIC

Code 4. No response was in scope. Set `use.baseURL` in the Playwright config or `scope.origins` in
the package config, and make sure the tests import `test` from your `fixtures.ts` built with
`withSecurityFixtures()`. Contexts created by hand need `security.track(context)`.
`gate.failOnNoTraffic: false` only reports it.

## Mode and config

### MODE_INVALID

`PW_SEC_MODE` has a value other than `scan` or `baseline` (case does not matter). Unset it to turn
the scan off.

### MODE_NOT_AVAILABLE

`PW_SEC_MODE=active` is reserved for the active scan of later versions. This version is passive
only.

### ENV_INVALID

`PW_SEC_ENV` is not an environment label. Use 1 to 32 lowercase letters, digits and `-`, starting
with a letter or a digit (e.g. `qa`, `staging-eu`). An invalid `run.env` in the config is reported
as `CONFIG_INVALID_VALUE`.

### MAX_TESTS_INVALID

`PW_SEC_MAX_TESTS` in a check (`PW_SEC_MODE=check`) is not a whole number from 1 to 1000. Outside a
check the variable is ignored.

### CONFIG_UNKNOWN_OPTION

An option name of the package config is unknown; the message names the closest valid one and the
allowed names.

### CONFIG_UNKNOWN_RULE

A key under `rules` is not a rule id; the message names the closest one (see
[docs/rules](rules/README.md)).

### CONFIG_INVALID_TYPE

An option has a value of the wrong type, e.g. a string where a number is expected.

### CONFIG_INVALID_VALUE

An option has a value outside its allowed set, or `scope.origins` holds something that is not an
origin (`scheme://host[:port]`, `*` only in subdomains).

### CONFIG_INVALID_REGEX

A `{ regex, flags }` entry of `normalization.extraIdPatterns` does not compile.

### CONFIG_FILE_UNREADABLE

`PW_SEC_CONFIG` points to a file that cannot be read. Use a `.json` file or a module whose default
export is the config.

### CONFIG_MISSING

The fixtures or the reporter run without `withSecurity()` on the Playwright config. Wrap the config:
`export default withSecurity(defineConfig({ … }))`.

### SCOPE_EMPTY

No origin is in scope: there is no `use.baseURL` and no `scope.origins`. The run will end with
`NO_TRAFFIC`.

### LOCAL_ORIGIN

The app runs on `localhost`; transport rules (HSTS, `Secure` cookies, cleartext) are reported with
low confidence and do not fail the scan. Scan a deployed HTTPS environment for real results.

### PERF_MODE_ACTIVE

`PW_PERF_MODE` is set together with `PW_SEC_MODE`. Body analysis adds load to the workers and may
distort the step timings of the perf package; run the two in separate CI jobs.

## Collection

### BODY_READ_FAILED

A response body could not be read, usually because the page or context closed while the body was
still arriving. Header rules still ran. If it happens often, avoid closing contexts in the middle
of requests.

### COLLECTOR_ERROR

A response or the CSP listener could not be processed; the test result is not affected. Report it
as a bug if it repeats.

### STORAGE_SCAN_FAILED

The end-of-test scan of cookies and Web Storage was skipped (closed page, timeout of 2 s). Storage
rules had no input for that test.

### API_ORIGIN_OUT_OF_SCOPE

An API test called an origin that is not in scope; its responses were only counted. Add the origin
to `scope.origins` to scan them.

### API_ANALYSIS_TIMEOUT

API responses were still being analysed 5 s after the test ended. Very large API bodies are the
usual cause; lower `limits.maxBodyBytes`.

### RULE_ERROR

A rule threw on some input and was switched off for the rest of that test. The test result is not
affected. Please report it with the rule id.

### RULE_FINDINGS_LIMIT

A rule reached `limits.maxFindingsPerRule` in one test; further findings of that rule in the test
were dropped.

### ATTACHMENT_TRUNCATED

The findings of one test were larger than 256 KB; evidence was cut to one item per finding.

### ATTACHMENT_INVALID

The reporter could not read the findings attachment of a test. Report it as a bug.

### NORMALIZE_UNSUPPORTED_URL

A request URL that is not http(s) or cannot be parsed was skipped when building endpoint keys.

### NORMALIZE_KEY_TRUNCATED

An endpoint key longer than 2000 characters was cut and suffixed with a hash.

### NORMALIZE_KEY_BUILDER_THREW

The `normalization.keyBuilder` function threw; the built-in normalization was used instead.

### NORMALIZE_KEY_BUILDER_INVALID

The `normalization.keyBuilder` function returned something other than a non-empty string or
`undefined`.

## Baseline

### BASELINE_INVALID

`security-baseline.json` cannot be used: invalid JSON, a `schemaVersion` other than 1, an entry with
a missing or wrong field, an unknown rule id, or a `wontfix` entry without a note. The message names
the entry and the field. The file is not overwritten by a baseline run until it is fixed. After a
merge conflict, keep both sides and run `PW_SEC_MODE=baseline`.

### BASELINE_RULE_OFF

An entry belongs to a rule switched off in the config; it is kept but not used.

### BASELINE_STALE_STATUS

A `false-positive` entry has an `until` date. False positives never expire; remove `until`.

### BASELINE_NOTE_REQUIRED

`baseline.requireNote` is on and accepted entries have no `note`. Add the reason of each decision.

### BASELINE_ENV_MISSING

**Warning.** An environment label is set (`PW_SEC_ENV` or `run.env`), its baseline file (e.g.
`security-baseline.qa.json`) does not exist, but the file without a label does. The file without a
label is not used for a labelled run, so every finding is new. Run
`PW_SEC_MODE=baseline PW_SEC_ENV=qa npx playwright test` and commit the new file, or copy the file
without a label to the labelled name.

### BASELINE_ENV_MISMATCH

**Warning.** The baseline file records another environment label (`"env"`) than the one of this
run, or the run has no label. Check `PW_SEC_ENV` and `run.env`; the findings are still classified
against the file.

### PARTIAL_RUN

A `baseline` run was filtered (`--grep`, `--project`, `--shard`, file arguments, `--only-changed`),
so entries not seen in it were kept rather than removed as resolved. Run the full suite to prune.

## Reporter

### REPORTER_ERROR

The reporter failed in one step (e.g. writing a file); the result is marked `TOOL_ERROR`. Check
file permissions of `report.dir` and `baseline.path`.

### RUN_REPORTER_FLAG

`--reporter` on the command line replaces the reporters of the Playwright config, so the security
reporter would not run and the scan could never fail. Add it to the flag
(`--reporter=dot,playwright-security-scan/reporter`) or drop `--reporter`.

## Setup wizard

Codes of `npm init playwright-security-scan` and `npx pw-sec`. Errors end the wizard with exit
code 3 before anything is written.

### INIT_INVALID_VALUE

`PW_SEC_LANG` is not one of `en`, `es`, `fr`, `pl`, `it`, `uk`, `ru`, or `PW_SEC_DRY_RUN` /
`PW_SEC_NO_TUTORIAL` is set to something other than `1`. Fix or unset the variable.

### INIT_NO_PLAYWRIGHT_CONFIG

There is no `playwright.config.*` in the current directory. Run the wizard in the directory of your
Playwright config; when configs are found in subdirectories, the message lists them with the
command to run there (`cd e2e && npx pw-sec`).

### INIT_PLAYWRIGHT_TOO_OLD

The project's `@playwright/test` is older than the lowest version the package supports (1.57).
Update it, then run the wizard again.

### INIT_MANUAL_STEP

**Warning.** The wizard left a change to you because it did not recognise the layout: a
`playwright.config` whose export is not a plain `defineConfig({...})`, `withPerf(...)` or object
(e.g. another wrapper), an existing `pw-sec.config.*` it does not rewrite, test files that still
import `test` from `@playwright/test`, or contexts from `request.newContext()` that are not
tracked. The message shows the code to paste.

### INIT_TEST_OBJECT_MANUAL

**Warning (red box).** The wizard could not wrap your test object or switch the imports of your test
files, so nothing would be scanned yet. Wrap the `test` of your fixtures module with
`withSecurityFixtures()`, or import `test` from `playwright-security-scan/test` in your test files;
see [Adoption](adoption.md).

### INIT_WRITE_FAILED

A file could not be written (permissions, a read-only folder). Files written before it stay. Fix
the permissions and run the wizard again: it only proposes what is still missing.

### CLI_UNKNOWN_COMMAND

`pw-sec` was given arguments. It has no commands or options: without arguments it starts the
setup wizard, and the scan itself runs with `PW_SEC_MODE` in front of your test command.

### CLI_INTERNAL_ERROR

An unexpected error in the wizard. This is a bug in the package: please report it with the message
and the stack trace.
