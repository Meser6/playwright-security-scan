# Guided setup

```sh
npm init playwright-security-scan
# or: pnpm create playwright-security-scan · yarn create playwright-security-scan
```

This installs `playwright-security-scan` as a dev dependency with the package manager of your
project (found by its lockfile) and starts the guided setup. In a project where the package is
already installed, `npx pw-sec` starts the same setup. Run it from the directory of your
Playwright config; you can run it again at any time: it only proposes what is still missing.

The setup asks its questions in a terminal. Without a terminal (for example in CI) it takes the
default answers, shows the planned changes and writes nothing.

| Variable               | Effect                                                                  |
| ---------------------- | ----------------------------------------------------------------------- |
| `PW_SEC_LANG=<code>`   | language without the question: `en`, `es`, `fr`, `pl`, `it`, `uk`, `ru` |
| `PW_SEC_DRY_RUN=1`     | show the planned changes only, write nothing                            |
| `PW_SEC_NO_TUTORIAL=1` | print the manual setup steps only, change nothing                       |

## The steps

0. **Tutorial and language.** "No" prints the two manual changes and ends without touching a
   file.
1. **The package and how to use it**: what the scan does and does not do, the commands
   (`check`, `baseline`, review and commit, `scan`) and the files to commit. A missing
   `playwright.config` ([`INIT_NO_PLAYWRIGHT_CONFIG`](troubleshooting.md#init_no_playwright_config))
   or a Playwright older than 1.57
   ([`INIT_PLAYWRIGHT_TOO_OLD`](troubleshooting.md#init_playwright_too_old)) stops here.
2. **Rules**: the preset, `recommended` (default), `strict` or `minimal`.
3. **Gate**: the lowest severity of a new finding that fails the scan (`medium`).
4. **Origins of your app**: the scope is the origin of `use.baseURL`; the step shows it and the
   other `http(s)://` origins written in your sources (without analytics, fonts and CDNs) and
   asks which ones to add to `scope.origins`, for example an API on another host.
5. **Environments**: when the same tests run against several environments, the labels for
   [one baseline per environment](baseline.md#one-baseline-per-environment). They only change the
   commands at the end, not the config.
6. **Test command**: the command you usually run your tests with (`npx playwright test` or the
   only script that runs `playwright test`). The wizard never changes it; it puts `PW_SEC_MODE`
   in front of it in the commands at the end and uses it for the check. `skip` keeps the
   suggestion and skips the check. A chain (`a && b`) or `--reporter` gets a warning.
7. **Changes**, each shown as a diff and applied only after your "yes":
   - a short `pw-sec.config.ts` (in a JavaScript project `.js`, `.mjs` or `.cjs` in the module
     system of your Playwright config) with the most important options and a comment on each;
     an existing package config is never rewritten;
   - `withSecurity()` around the export of `playwright.config`; with
     `playwright-performance-regression` it goes **outside** `withPerf()`, and a reversed order
     is fixed;
   - `withSecurityFixtures()` around the `test` of your fixtures module, or, without one, the
     import of `test` and `expect` from `playwright-security-scan/test` in each test file (setup
     files are left alone);
   - `reports/pw-sec/` in `.gitignore`, unless it is ignored already.

   `package.json` is never changed and no CI job is added. A layout the wizard does not recognise
   (another config wrapper, `mergeTests`, several test objects) is left to you with the code to
   paste ([`INIT_MANUAL_STEP`](troubleshooting.md#init_manual_step),
   [`INIT_TEST_OBJECT_MANUAL`](troubleshooting.md#init_test_object_manual)).

8. **Check** (optional): your test command runs three times, as real runs:
   `PW_SEC_MODE=check`, then `baseline` and `scan` with the baseline in a temporary folder that is
   removed afterwards, so your project's baseline is not created yet. A failure is explained:
   no response in scope (with the fix in the config), a tool error, or new findings right after
   the baseline (traffic that differs between runs).
9. **Summary** with an IMPORTANT box: the exact commands for your project to accept the baseline
   (one per environment label), what to review, what to commit, and the scan to run in CI. On
   Windows the commands start with `npx cross-env`; see [Windows](cli.md#windows).

Then copy a [CI recipe](ci.md) and put your scan command in it.
