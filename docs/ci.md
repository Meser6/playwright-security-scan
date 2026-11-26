# CI

Run your usual test command with `PW_SEC_MODE=scan` and keep `reports/pw-sec/` as an artifact.
Upload `results.sarif` where your security dashboard reads it, and `junit.xml` where your CI shows
test results. The examples run the scan in its own job, next to your normal e2e job.

Commit `security-baseline.json` (one file per [environment](#environments)); CI only reads it.

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

When the same tests run against several environments, give each one its own baseline with
`PW_SEC_ENV`:

```yaml
# GitHub Actions
strategy:
  matrix:
    env: [qa, staging]
steps:
  # …
  - run: npx playwright test
    env:
      PW_SEC_MODE: scan
      PW_SEC_ENV: ${{ matrix.env }}
      BASE_URL: ${{ vars[format('BASE_URL_{0}', matrix.env)] }}
  - uses: github/codeql-action/upload-sarif@v3
    if: always()
    with:
      sarif_file: reports/pw-sec/results.sarif
      category: playwright-security-scan-${{ matrix.env }}
```

Each job reads `security-baseline.<env>.json`. Use a separate SARIF category per environment, so
one environment's upload does not close the alerts of another. See
[One baseline per environment](baseline.md#one-baseline-per-environment).

## Schedule

Findings depend on the server, not only on your code: a proxy change can drop a header overnight.
A scheduled scan of the main branch catches that between merges:

```yaml
on:
  schedule:
    - cron: '0 5 * * 1-5'
```

## Updating the baseline

Do not run `baseline` mode in CI on every build: it would accept every new finding. Run it locally
(or in a manual job that opens a pull request), review the diff and commit it like code.

## With playwright-performance-regression

Run the security scan and the performance measurement in **separate jobs**: analysing response
bodies adds load to the workers that can distort timings. See
[Together with performance regression](adoption.md#together-with-playwright-performance-regression).
