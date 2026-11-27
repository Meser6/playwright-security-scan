# CLAUDE.md

Guidance for Claude Code (and any contributor) working in this repository.

## Project

`playwright-security-scan` is an npm package for Playwright Test. In a scan run (the user's own
test command with `PW_SEC_MODE=scan`) it passively analyses the HTTP traffic of existing e2e tests
(browser contexts) and API tests (`APIRequestContext`), plus browser state (CSP violations, Web
Storage), with a catalog of passive security rules. Findings are deduplicated by fingerprint,
compared with a baseline file committed to the user's repository (`security-baseline.json`), and
only new findings above the gate fail the run. Reports: console, JSON, HTML, SARIF, JUnit XML.

The package is passive by default: it never sends a request of its own and never modifies the
test's requests (P-04). The only exception is opt-in: the authorization tests (`authz.enabled`)
replay GET/HEAD requests after the tests, from `src/active/` (loaded with `import()` only then).

## Specification

- The specification lives in a **separate private repository**, expected as a sibling checkout:
  `../npm-spec/security/` (`spec/`, `v1_todo.md`, `HANDOFF.md`). Read the relevant spec files
  before working on a task.
- The spec is the source of truth. If code and spec disagree, the spec wins; if the spec is wrong,
  it is changed and pushed in the spec repository **first**, then the code follows.
- Never copy spec text, roadmap or business details into this public repository. Refer to spec
  items by ID only (e.g. `05-REQ-14`, `09-AC-03`, `D-12`).
- `spec-ids.json` (exported from the spec repo) lists valid IDs for the AC coverage check.
- The sibling package `playwright-performance-regression` (`../playwright-performance-regression`)
  is the technical model: fixtures, registry, `APIRequestContext` wrapping, normalization and
  tooling follow it. It is read-only from here.

## Work process

- Work follows `v1_todo.md` in the spec repo: one work package = one branch = one PR.
- Acceptance-criteria tests are written before the code. A test covering an AC has the AC ID in
  its title, e.g. `test('08-AC-02 expired baseline entry fails with code 2', ...)`.
- Definition of done for a work package:
  1. AC tests exist and pass;
  2. lint, format, typecheck and all tests pass locally;
  3. the AC coverage check reports no gaps for the implemented criteria;
  4. spec deviations were pushed in the spec repo first and `spec-ids.json` is refreshed;
  5. `CHANGELOG.md` has an entry for user-visible changes;
  6. the work is on its own branch and the PR is merged after green CI.

## Hard constraints

- No runtime dependencies, no telemetry, no install/lifecycle scripts.
- The package never calls `route()` and sends requests only from `src/active/`, which is loaded
  only with `authz.enabled` (P-04 v0.4): GET/HEAD to `authz.allowedOrigins`, never production.
- `src/core/` is pure: no imports from Node built-ins or Playwright; deterministic output.
- Response bodies never leave the worker; every evidence snippet is redacted (P-07). No cookie,
  token or secret value may reach any file.
- Only public Playwright APIs.
- Outside scan mode the package must not change Playwright behaviour or add overhead (P-02).
- Public docs, messages, report texts, code identifiers and commit messages are in English.

## Git workflow

- Never commit to `main` directly and never rewrite `main` history. Claude squash-merges its own
  PRs once CI is green (`gh pr merge --squash`); the owner delegated review and merge.
- Branch per work package: `<type>/<short-name>` (e.g. `feat/collector`, `test/quality`).
- Conventional Commits, English, imperative mood, subject ≤ 72 characters, no trailing period:

  ```
  <type>(<scope>): <subject>

  <body: what and why, wrapped at 72>

  Refs: 05-REQ-14, 05-AC-01
  Spec: npm-spec@<short spec commit>
  Co-Authored-By: Claude <model> <noreply@anthropic.com>
  ```

  - types: `feat`, `fix`, `perf`, `refactor`, `test`, `docs`, `build`, `ci`, `chore`, `revert`
  - scopes: see `scripts/check-pr-title.mjs`

- PR title follows Conventional Commits (it becomes the squash commit subject). Fill in
  `.github/pull_request_template.md`. Only squash merges.

## Commands

Requires Node >= 22.18.0 and pnpm (version pinned in `packageManager`; `corepack enable`).

```sh
pnpm install                 # install dev dependencies (frozen lockfile in CI)
pnpm build                   # tsup: ESM + CJS + declarations per entry point into dist/
pnpm typecheck               # tsc --noEmit (src, test, scripts)
pnpm lint                    # ESLint, including the src/core purity rules
pnpm format                  # Prettier --write; `pnpm format:check` in CI
pnpm test                    # Vitest: unit, contract and integration tests
                             # (integration runs Playwright on dist/: `pnpm build` first)
pnpm check:ac                # AC coverage for the criteria in scripts/ac-scope.json (--all: every AC)
pnpm check:pr-title "<title>"   # validate a PR title
pnpm publint && pnpm attw    # package exports check (after `pnpm build`)
```

- `spec-ids.json` is regenerated, never edited: run
  `node ../npm-spec/security/scripts/export-spec-ids.mjs --out spec-ids.json` from this repository.
- When a work package implements acceptance criteria, add them (or the whole spec file prefix) to
  `scripts/ac-scope.json`; manual or out-of-CI criteria go to `scripts/ac-manual.json`.
