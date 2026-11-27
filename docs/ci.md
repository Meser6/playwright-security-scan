# CI

Run your usual test command with `PW_SEC_MODE=scan` and keep `reports/pw-sec/` as an artifact.
Upload `results.sarif` where your security dashboard reads it, and `junit.xml` where your CI shows
test results. The examples run the scan in its own job, next to your normal e2e job.

Commit `security-baseline.json`; CI only reads it.

## GitHub Actions

SARIF in the Security tab (code scanning), the reports as an artifact:

```yaml
name: security-scan
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write # upload-sarif

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: npm
      - run: npm ci
      - run: npx playwright install --with-deps chromium
      - run: npx playwright test
        env:
          PW_SEC_MODE: scan
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: reports/pw-sec/results.sarif
          category: playwright-security-scan
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: pw-sec
          path: reports/pw-sec/
```

`if: always()` uploads the reports also when the scan fails, which is when you need them. Code
scanning on private repositories needs GitHub Advanced Security; without it, skip the SARIF step
and use the HTML report from the artifact.

## GitLab CI

```yaml
security-scan:
  image: mcr.microsoft.com/playwright:v1.57.0-noble
  script:
    - npm ci
    - PW_SEC_MODE=scan npx playwright test
  artifacts:
    when: always
    paths: [reports/pw-sec/]
    reports:
      junit: reports/pw-sec/junit.xml
```

The merge request widget shows the findings as the `pw-sec` test suite: new blocking findings as
failures, with the evidence and the fix. GitLab Ultimate users can also convert
`results.sarif`; the JUnit view works on every tier.

## Azure DevOps

```yaml
- script: npm ci && npx playwright install --with-deps chromium
- script: npx playwright test
  env:
    PW_SEC_MODE: scan
- task: PublishTestResults@2
  condition: always()
  inputs:
    testResultsFormat: JUnit
    testResultsFiles: reports/pw-sec/junit.xml
    testRunTitle: pw-sec
- task: PublishPipelineArtifact@1
  condition: always()
  inputs:
    targetPath: reports/pw-sec
    artifact: pw-sec
```

## Jenkins

```groovy
stage('Security scan') {
  environment { PW_SEC_MODE = 'scan' }
  steps {
    sh 'npm ci'
    sh 'npx playwright test'
  }
  post {
    always {
      junit 'reports/pw-sec/junit.xml'
      archiveArtifacts artifacts: 'reports/pw-sec/**', allowEmptyArchive: true
    }
  }
}
```

With the Warnings Next Generation plugin, `recordIssues(tools: [sarif(pattern:
'reports/pw-sec/results.sarif')])` shows the SARIF findings too.

## Why did it fail?

The Playwright command exits with 1 for failing tests and for a failing scan. To tell them apart,
read `reports/pw-sec/outcome.json`:

```sh
node -e "const o=require('./reports/pw-sec/outcome.json'); console.log(o.name, 'tests passed:', o.testsPassed)"
```

`code` 1 means new findings, 2 expired baseline entries, 3 a tool error (fix the config or the
baseline file), 4 no traffic in scope. See [Exit code and result](cli.md#exit-code-and-result).

## Environments

One job scans one environment with one baseline file. To scan several environments with their own
baselines, set `baseline.path` from your own variable and give each SARIF upload its own
`category`; see [Several environments](faq.md#several-environments).

## Schedule

Findings depend on the server, not only on your code: a proxy change can drop a header overnight.
A scheduled scan of the main branch catches that between merges:

```yaml
on:
  schedule:
    - cron: '0 5 * * 1-5'
```

## Nightly attack run

The [attack mode](attack.md) sends attacks to your app, so it belongs in a nightly (or manual) job
against an environment your team may attack, never in pull requests. On `ubuntu-latest` Docker is
there and the ZAP container reaches the app the job starts on `localhost`:

```yaml
name: Nightly attack
on:
  schedule:
    - cron: '0 2 * * *'
  workflow_dispatch:

permissions:
  contents: read
  security-events: write # upload-sarif

jobs:
  attack:
    runs-on: ubuntu-latest
    # At least attack.maxDurationMinutes plus the time of the tests.
    timeout-minutes: 60
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: npm ci
      - run: npx playwright install --with-deps chromium
      - run: docker pull zaproxy/zap-stable
      - run: npm run start:test & npx wait-on http://localhost:3000
      - run: npx playwright test
        env:
          PW_SEC_MODE: attack
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: reports/pw-sec/results.sarif
          category: pw-sec-attack
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: pw-sec-attack
          path: reports/pw-sec/
```

`attack.allowedOrigins` in `pw-sec.config.ts` lists `http://localhost:3000`, the app of the job.
Review new `zap.*` findings, then accept them with an `attack-baseline` run (or by hand in
`security-baseline.json`) like any other finding.

## Sharded runs

A large suite often runs on several machines with Playwright's `--shard=i/n`. Each shard then sees
only part of the traffic, so it cannot judge the findings or write the baseline on its own. Add a
merge job instead:

1. **Shard jobs** run your usual test command with `PW_SEC_MODE=scan` (or `baseline`) and
   `--shard=i/n`. A shard does not read the baseline and writes no report: it writes
   `reports/pw-sec/shard-<i>-of-<n>.json` and `outcome.json` (`SHARD_WRITTEN`, or `TOOL_ERROR`
   when something went wrong). The console ends with
   `Next: when all n shards are done, run PW_SEC_MODE=merge npx pw-sec in the merge job`.
2. **The merge job** downloads the shard files of all shards to `reports/pw-sec/` and runs
   `PW_SEC_MODE=merge npx pw-sec`. It needs no browsers and no app, only the checkout (with
   `security-baseline.json`) and `npm ci`. It deduplicates the findings of all shards, compares
   them with the baseline once and writes one `report.json`, `report.html`, `results.sarif`,
   `junit.xml` and `outcome.json`. Its exit code is the result code (0, 1, 2, 3 or 4) like a run
   without shards; the summary says `merged from 3 shards`.

### GitHub Actions

```yaml
name: security-scan
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write # upload-sarif

jobs:
  shard:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        shard: [1, 2, 3] # also change the 3 in --shard below
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: npm
      - run: npm ci
      - run: npx playwright install --with-deps chromium
      - run: npx playwright test --shard=${{ matrix.shard }}/3
        env:
          PW_SEC_MODE: scan
      - name: Upload the shard file
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: pw-sec-shard-${{ matrix.shard }}
          path: reports/pw-sec/shard-*.json
          retention-days: 7

  merge:
    needs: shard
    if: always()
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: npm
      - run: npm ci
      - uses: actions/download-artifact@v4
        with:
          pattern: pw-sec-shard-*
          path: reports/pw-sec
          merge-multiple: true
      - run: npx pw-sec
        env:
          PW_SEC_MODE: merge
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: reports/pw-sec/results.sarif
          category: playwright-security-scan
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: pw-sec
          path: reports/pw-sec/
```

### GitLab CI

```yaml
security-scan-shard:
  image: mcr.microsoft.com/playwright:v1.57.0-noble
  parallel: 3
  script:
    - npm ci
    - PW_SEC_MODE=scan npx playwright test --shard=$CI_NODE_INDEX/$CI_NODE_TOTAL
  artifacts:
    when: always
    paths: [reports/pw-sec/shard-*.json]
    expire_in: 7 days

security-scan-merge:
  image: node:22
  needs: [security-scan-shard]
  when: always
  script:
    - npm ci
    - PW_SEC_MODE=merge npx pw-sec
  artifacts:
    when: always
    paths: [reports/pw-sec/]
    reports:
      junit: reports/pw-sec/junit.xml
```

Rules for sharded runs:

- **Upload only the `shard-*.json` files** (`outcome.json` has the same name on every machine) and
  upload them also when the tests failed (`if: always()`, `when: always`). A missing shard is
  `MERGE_SHARD_MISSING` (exit code 3): the report covers the other shards and no baseline is
  written.
- **The number of shards is in two places**: the matrix (or `parallel:`) and `--shard=i/n`. Keep
  them equal; shard files with different totals are rejected (`MERGE_SHARD_MISMATCH`), as are
  files of another package version, mode or config.
- **Run the merge from the root of the checkout**, the directory where the shards ran the test
  command: it finds the Playwright config and `security-baseline.json` from there
  (`MERGE_WRONG_DIRECTORY` otherwise). The merge always reads and writes `reports/pw-sec/` of the
  working directory, also with your own `report.dir`.
- **A new baseline through shards:** run the shard jobs with `PW_SEC_MODE=baseline`; the merge
  job writes the complete `security-baseline.json` (keep it as an artifact, download, review and
  commit it). Resolved entries are removed only when no shard was filtered (`--grep`,
  `--project`, files) and no shard is missing; otherwise `PARTIAL_RUN` keeps them.
- `PW_SEC_MODE=check` with `--shard` checks only the tests of that shard and writes no shard file.
- **Testing the merge locally:** run the shards one after another in separate copies of the
  project, copy their `shard-*.json` files into `reports/pw-sec/` of one checkout and run
  `PW_SEC_MODE=merge npx pw-sec` there.

## Updating the baseline

Do not run `baseline` mode in CI on every build: it would accept every new finding. Run it locally
(or in a manual job that opens a pull request), review the diff and commit it like code.

## With playwright-performance-regression

Run the security scan and the performance measurement in **separate jobs**: analysing response
bodies adds load to the workers that can distort timings. See
[Together with performance regression](adoption.md#together-with-playwright-performance-regression).
