# Running the scan

The scan has no command of its own (the only binary, `npx pw-sec`, starts the
[guided setup](init.md)). You run your usual Playwright test command with
`PW_SEC_MODE` set:

| Goal                     | Command                                         |
| ------------------------ | ----------------------------------------------- |
| dry run (check)          | `PW_SEC_MODE=check npx playwright test`         |
| accept the current state | `PW_SEC_MODE=baseline npx playwright test`      |
| scan (CI and locally)    | `PW_SEC_MODE=scan npx playwright test`          |
| scan with an npm script  | `PW_SEC_MODE=scan npm run e2e`                  |
| scan of one environment  | `PW_SEC_MODE=scan PW_SEC_ENV=qa npm run e2e:qa` |

Run the command from the directory you always run your tests from. Everything your script does
still happens: its variables, setup steps and Playwright flags. Without `PW_SEC_MODE` your tests
run exactly as before: the package adds no listener, no script and no reporter.

## Modes

| `PW_SEC_MODE` | Tests run      | Analysis | Files written                        | Fails the run on              |
| ------------- | -------------- | -------- | ------------------------------------ | ----------------------------- |
| (unset)       | all            | no       | none                                 | —                             |
| `check`       | first per file | yes      | none                                 | — (Playwright's exit code)    |
| `baseline`    | all            | yes      | reports and `security-baseline.json` | tool errors, no traffic       |
| `scan`        | all            | yes      | reports                              | new findings, expired entries |

The value is case-insensitive. `active` is reserved for the active scan of later versions and
stops the run with [`MODE_NOT_AVAILABLE`](troubleshooting.md#mode_not_available); any other value
stops it with [`MODE_INVALID`](troubleshooting.md#mode_invalid).

Playwright filters (`--grep`, `--project`, `--shard`, file arguments) work as usual. A `baseline`
run with a filter keeps the entries it could not confirm as resolved; see
[Partial runs](baseline.md#partial-runs).

## Variables

| Variable           | Meaning                                                                                                           |
| ------------------ | ----------------------------------------------------------------------------------------------------------------- |
| `PW_SEC_MODE`      | `check`, `baseline` or `scan`; the package is off when it is unset or empty                                       |
| `PW_SEC_ENV`       | environment label: the run uses `security-baseline.<label>.json`; overrides `run.env` of the config               |
| `PW_SEC_MAX_TESTS` | in a check: tests to run, 1 to 1000 (default 10)                                                                  |
| `PW_SEC_CONFIG`    | path of a package config file (`.json`, or a module with a default export); wins over `withSecurity()`'s argument |
| `PW_SEC_RUN_ID`    | id of the run, set by the package for the workers; do not set it yourself                                         |
| `PW_SEC_RUN_SALT`  | redaction salt of the run, set by the package; do not set it yourself                                             |

`PW_SEC_ENV` is 1 to 32 lowercase letters, digits and `-`, starting with a letter or a digit. An
invalid label stops the run before the tests with [`ENV_INVALID`](troubleshooting.md#env_invalid);
an invalid `PW_SEC_MAX_TESTS` with [`MAX_TESTS_INVALID`](troubleshooting.md#max_tests_invalid).

## Windows

`VAR=value command` is shell syntax of Linux and macOS. On Windows:

```sh
# any shell, with the cross-env package
npx cross-env PW_SEC_MODE=scan npx playwright test

# PowerShell
$env:PW_SEC_MODE="scan"; npx playwright test

# cmd.exe
set PW_SEC_MODE=scan&& npx playwright test
```

In PowerShell the variable stays set for the rest of the session: `Remove-Item Env:PW_SEC_MODE`
turns the package off again. In npm scripts that must work everywhere, prefer `cross-env`.

## Dry run (check)

```sh
PW_SEC_MODE=check npx playwright test
PW_SEC_MODE=check PW_SEC_MAX_TESTS=20 npx playwright test
```

A dry run before the first baseline, or after changing the scope. It runs the first test of each
file of the scanned projects, up to `PW_SEC_MAX_TESTS` tests (default 10); projects outside
`scope.projects` (for example `setup`) run in full. It prints:

- the origins in scope, where each one comes from (`baseURL` or `scope.origins`) and how many
  responses and documents the scan saw on it; an origin with no response is marked;
- the traffic outside the scope (the five busiest origins) with the hint to add your own API to
  `scope.origins`;
- the scanned projects, the responses of API tests, the enabled rules, the state of the baseline
  file and how many findings of this check would be new;
- a verdict: `READY`, `READY WITH WARNINGS` or `NOT READY` (no response in scope, or an error).

The skipped tests are skipped by the package fixture before their body; `beforeAll` hooks of their
files may still run, and tests that import `test` straight from `@playwright/test` are not skipped
(they also produce no traffic for the scan). Nothing is written and the exit code is Playwright's.

## Exit code and result

In `scan` and `baseline` mode the package reporter decides the result of the scan and writes it to
`reports/pw-sec/outcome.json`:

| Code | Name               | Meaning                                                                |
| ---- | ------------------ | ---------------------------------------------------------------------- |
| 0    | `OK`               | No new finding at or above the gate.                                   |
| 1    | `NEW_FINDINGS`     | At least one new finding at or above the gate.                         |
| 2    | `BASELINE_EXPIRED` | A baseline entry passed its `until` date and the finding still occurs. |
| 3    | `TOOL_ERROR`       | The scan could not be trusted (e.g. an invalid baseline file).         |
| 4    | `NO_TRAFFIC`       | No response was in scope: set `use.baseURL` or `scope.origins`.        |

Any code other than 0 makes the Playwright command exit with 1; failing functional tests do too,
as always. `outcome.json` keeps the two apart (`code` and `testsPassed`), so CI can tell a security
failure from a test failure. In a `baseline` run new findings never fail the run.

## Console output

The run starts with a banner (mode, environment, scope, rules, gate, baseline, report) and ends
with a summary of at most 30 lines: errors and warnings in boxes, the counters and the blocking
findings in tables, the verdict in a box (`✅ PASSED`, `⚠ PASSED WITH WARNINGS`, `❌ FAILED`,
`❌ ERROR`) with the result name and code, and one `Report:` line with the absolute path of the
HTML report. A `baseline` run also prints the diff of the baseline file.

## Colors

The banner, the summary and the check use the 16 ANSI colors when the output is a terminal and
`TERM` is not `dumb`. Green means success, red a blocking finding or an error, yellow a warning,
magenta a tool error (the result is not trustworthy), cyan the banner and commands, dim hints, bold
headings. Every colored item also has an emoji or a word, and the text is the same without colors.

| Variable        | Effect                                                       |
| --------------- | ------------------------------------------------------------ |
| `NO_COLOR=1`    | No colors, also in a terminal and with `FORCE_COLOR`.        |
| `FORCE_COLOR=1` | Colors also without a terminal (for example in CI logs).     |
| `FORCE_COLOR=0` | No colors.                                                   |
| `TERM=dumb`     | No colors, ASCII frames (`+`, `-`, `\|`), `✔ ! ✖` for emoji. |

Without a terminal the output is 120 columns wide.
