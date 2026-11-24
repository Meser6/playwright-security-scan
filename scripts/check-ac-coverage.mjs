#!/usr/bin/env node
// @ts-check
// Acceptance criteria coverage check (10-REQ-01, 13-REQ-05).
//
// Compares the acceptance criteria IDs (NN-AC-NN) listed in spec-ids.json with the IDs found
// in test titles under test/. Fails when:
//   - a test title contains an AC ID that is not in spec-ids.json (stale or mistyped ID);
//   - scripts/ac-manual.json or scripts/ac-scope.json names an ID that is not in spec-ids.json;
//   - an AC that is in scope has no test and is not listed in scripts/ac-manual.json;
//   - a test title or scripts/ac-manual.json names a withdrawn AC.
//
// Withdrawn criteria. spec-ids.json marks criteria that no longer apply with "withdrawn": true.
// They never need a test, also with --all or a spec file prefix in scope, and no test may
// keep naming them, so that the tests of a removed feature do not stay in the repository.
//
// Scope. The package is implemented work package by work package, so most ACs have no code
// yet. scripts/ac-scope.json lists what is in scope; every entry is either
//   - a spec file prefix such as "07": all ACs of that spec file are in scope, or
//   - a single AC ID such as "13-AC-13".
// A work package adds the ACs it implements to the list (or the file prefix once a spec file
// is fully implemented). Run with --all to check every AC regardless of the scope; the full
// check becomes the CI default once everything is in scope.
//
// Manual criteria. scripts/ac-manual.json lists criteria verified by hand or outside the
// regular CI, each with a short description of how it is verified. They count as
// covered. Success criteria (S-NN) are allowed there although spec-ids.json does not list them.
//
// Test titles. A title is the first string argument of test(), it() or describe() (including
// modifiers such as test.skip or describe.each). AC IDs anywhere in such a title count.
//
// Usage: node scripts/check-ac-coverage.mjs [--all] [--root <dir>]
// No dependencies; Node built-ins only.
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const AC_ID = /\b\d\d-AC-\d+[a-z]?\b/g;
const SPEC_FILE = /^\d\d$/;
const SUCCESS_CRITERION = /^S-\d\d$/;
const TEST_FILE = /\.(?:test|spec)\.(?:[cm]?[jt]s)$/;
// test('title', ...), it.only("title", ...), describe(`title`, ...): the string literal right
// after the opening parenthesis of the call is the title.
const TITLE = /\b(?:test|it|describe)(?:\.[A-Za-z]+)*\(\s*(['"`])((?:\\.|(?!\1)[^\\])*)\1/g;

/**
 * @param {string} path
 * @returns {any}
 */
function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

/**
 * @param {string} dir
 * @returns {string[]}
 */
function listTestFiles(dir) {
  /** @type {string[]} */
  const files = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules') continue;
    const path = join(dir, entry.name);
    if (entry.isDirectory()) files.push(...listTestFiles(path));
    else if (TEST_FILE.test(entry.name)) files.push(path);
  }
  return files.sort();
}

/**
 * Returns the unique AC IDs found in the test titles of one source file.
 * @param {string} source
 * @returns {string[]}
 */
export function acIdsInTitles(source) {
  /** @type {Set<string>} */
  const ids = new Set();
  for (const match of source.matchAll(TITLE)) {
    for (const id of (match[2] ?? '').matchAll(AC_ID)) ids.add(id[0]);
  }
  return [...ids];
}

/**
 * @typedef {object} CoverageResult
 * @property {string[]} missing      in-scope ACs without a test or a manual entry
 * @property {Array<{ id: string, where: string }>} unknown  IDs not in spec-ids.json
 * @property {Array<{ id: string, where: string }>} withdrawn  withdrawn IDs still named
 * @property {number} inScope        number of in-scope ACs
 * @property {number} covered        number of in-scope ACs with a test or a manual entry
 */

/**
 * @param {{ root: string, all?: boolean }} options
 * @returns {CoverageResult}
 */
export function checkAcCoverage({ root, all = false }) {
  const specIds = readJson(join(root, 'spec-ids.json'));
  /** @type {{ id: string, kind: string, withdrawn?: boolean }[]} */
  const entries = specIds.ids.filter((/** @type {{kind: string}} */ e) => e.kind === 'AC');
  /** @type {Set<string>} */
  const acs = new Set(entries.filter((e) => e.withdrawn !== true).map((e) => e.id));
  /** @type {Set<string>} */
  const withdrawnIds = new Set(entries.filter((e) => e.withdrawn === true).map((e) => e.id));
  const manual = readJson(join(root, 'scripts/ac-manual.json'));
  const scope = readJson(join(root, 'scripts/ac-scope.json'));

  /** @type {Array<{ id: string, where: string }>} */
  const unknown = [];
  /** @type {Array<{ id: string, where: string }>} */
  const withdrawn = [];

  /** @type {Set<string>} */
  const manualIds = new Set();
  for (const entry of manual.criteria) {
    if (acs.has(entry.id) || SUCCESS_CRITERION.test(entry.id)) manualIds.add(entry.id);
    else if (withdrawnIds.has(entry.id))
      withdrawn.push({ id: entry.id, where: 'scripts/ac-manual.json' });
    else unknown.push({ id: entry.id, where: 'scripts/ac-manual.json' });
  }

  /** @type {Set<string>} */
  const scopeFiles = new Set();
  /** @type {Set<string>} */
  const scopeIds = new Set();
  for (const entry of scope.inScope) {
    if (SPEC_FILE.test(entry)) scopeFiles.add(entry);
    else if (acs.has(entry)) scopeIds.add(entry);
    else if (withdrawnIds.has(entry)) withdrawn.push({ id: entry, where: 'scripts/ac-scope.json' });
    else unknown.push({ id: entry, where: 'scripts/ac-scope.json' });
  }

  /** @type {Set<string>} */
  const tested = new Set();
  const testDir = join(root, 'test');
  for (const file of existsSync(testDir) ? listTestFiles(testDir) : []) {
    const where = relative(root, file).split('\\').join('/');
    for (const id of acIdsInTitles(readFileSync(file, 'utf8'))) {
      if (acs.has(id)) tested.add(id);
      else if (withdrawnIds.has(id)) withdrawn.push({ id, where });
      else unknown.push({ id, where });
    }
  }

  const inScope = [...acs].filter(
    (id) => all || scopeIds.has(id) || scopeFiles.has(id.slice(0, 2)),
  );
  const missing = inScope.filter((id) => !tested.has(id) && !manualIds.has(id));
  return {
    missing,
    unknown,
    withdrawn,
    inScope: inScope.length,
    covered: inScope.length - missing.length,
  };
}

function main() {
  const args = process.argv.slice(2);
  const rootIndex = args.indexOf('--root');
  const root =
    rootIndex >= 0 && args[rootIndex + 1]
      ? args[rootIndex + 1]
      : join(fileURLToPath(new URL('.', import.meta.url)), '..');
  const all = args.includes('--all');
  const result = checkAcCoverage({ root: String(root), all });

  for (const id of result.missing) {
    console.error(`check-ac-coverage: ${id} has no test (no test title contains it)`);
  }
  for (const { id, where } of result.unknown) {
    console.error(`check-ac-coverage: ${id} in ${where} is not an AC in spec-ids.json`);
  }
  for (const { id, where } of result.withdrawn) {
    console.error(
      `check-ac-coverage: ${id} in ${where} is withdrawn; remove it together with the removed feature`,
    );
  }
  const summary = `${result.covered}/${result.inScope} acceptance criteria ${all ? '' : 'in scope '}covered`;
  if (result.missing.length > 0 || result.unknown.length > 0 || result.withdrawn.length > 0) {
    console.error(`check-ac-coverage: failed, ${summary}`);
    process.exit(1);
  }
  console.log(`check-ac-coverage: ok, ${summary}`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main();
