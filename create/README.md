# create-playwright-security-scan

Sets up [playwright-security-scan](https://github.com/Meser6/playwright-security-scan)
in an existing Playwright project with one command:

```sh
npm init playwright-security-scan
# or: pnpm create playwright-security-scan · yarn create playwright-security-scan
```

It installs `playwright-security-scan` as a dev dependency with the package manager of the
project (found by its lockfile) and starts the guided setup. In a project where the package is
already installed it only starts the setup, so you can run it again at any time.

The command takes no arguments. The setup asks its questions in a terminal (without a terminal it
only shows the planned changes); these variables change it:

| Variable               | Effect                                                                         |
| ---------------------- | ------------------------------------------------------------------------------ |
| `PW_SEC_LANG=<code>`   | wizard language without the question: `en`, `es`, `fr`, `pl`, `it`, `uk`, `ru` |
| `PW_SEC_DRY_RUN=1`     | show the planned changes only, write nothing                                   |
| `PW_SEC_NO_TUTORIAL=1` | print the manual setup steps only, change nothing                              |
