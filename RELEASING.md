# Releasing

Releases are published by `.github/workflows/release.yml` when the owner pushes a tag `vX.Y.Z`
or `vX.Y.Z-<next|beta|rc>.N` on `main`. The workflow:

1. checks that the tag points to a commit on `main`, that it equals `version` in `package.json`
   **and** `create/package.json`, that `CHANGELOG.md` has a `## [X.Y.Z…]` section, and that
   neither `package.json` has `"private": true` (`scripts/check-release.mjs`); otherwise it stops
   before anything is published;
2. runs the CI (`ci.yml`) on the tagged commit;
3. builds and **stages** both packages on npm from the `npm` environment with npm provenance
   through trusted publishing (OIDC, no npm token, `npm stage publish`): dist-tag `next` for a
   pre-release, `latest` otherwise; a version already on npm is skipped, so a failed run can be
   re-run for the same tag. Staged versions are not public until the owner approves them;
4. creates the GitHub Release with the CHANGELOG section as notes (a pre-release for `next`).

## Approving a release

1. Approve `playwright-security-scan` first (the create package installs it), then
   `create-playwright-security-scan`: on npmjs.com, package → **Staged versions** → **Approve**
   (2FA), or `npm stage list <package>` and `npm stage approve <stage-id>`.
2. Check: `npm view playwright-security-scan@next version` (or `@latest`).
3. Check the create package by hand in a fresh Playwright project:
   `npm init playwright-security-scan@next` and `pnpm create playwright-security-scan@next`
   (manual criterion 11-AC-08).

A staged version that should not be released is rejected with `npm stage reject <stage-id>`.
Release tags are never moved or deleted.

## One-time owner setup

1. **npm trusted publishing** for `playwright-security-scan` and
   `create-playwright-security-scan` (npm account with 2FA): npmjs.com → package → Settings →
   Trusted Publisher → GitHub Actions, user `Meser6`, repository `playwright-security-scan`,
   workflow `release.yml`, environment `npm`; allow **stage publish** only. The create package
   does not exist on npm yet: publish a placeholder `0.0.0` by hand first, like the main package.
2. **GitHub environment `npm`**: Settings → Environments → New environment `npm`; restrict it to
   tags `v*` (deployment tags rule). No secrets are needed.
3. **Required status checks** of `main`: `Checks`, every `Test (…)` job, `PR title`, `CHANGELOG`
   (the `Browsers (…)` jobs and the macOS cell are informational).

## Releasing a version

1. On a release branch: set `version` in `package.json` and `create/package.json`, move the
   `## [Unreleased]` entries of `CHANGELOG.md` to `## [X.Y.Z…] - YYYY-MM-DD`, open a PR, merge it.
2. Tag the merge commit and push the tag: `git tag vX.Y.Z-beta.N && git push origin vX.Y.Z-beta.N`.
3. Approve the staged versions (above).
