#!/usr/bin/env node
// @ts-check
// Checks that a pull request title follows Conventional Commits as used by this repository
// (13-REQ-03). The title becomes the subject of the squash commit on main.
//
// Rules: `<type>[(<scope>)][!]: <subject>` with a known type and scope, at most 72 characters
// in total, a subject that starts with a lowercase letter or a digit and has no trailing period.
// Exception: Dependabot titles in the deps scope may start with "Bump ".
//
// Usage: node scripts/check-pr-title.mjs "<title>"   (or PR_TITLE in the environment)
// No dependencies; Node built-ins only.
import { fileURLToPath } from 'node:url';

export const TYPES = [
  'feat',
  'fix',
  'perf',
  'refactor',
  'test',
  'docs',
  'build',
  'ci',
  'chore',
  'revert',
];
export const SCOPES = [
  'core',
  'config',
  'mode',
  'collector',
  'fixture',
  'api',
  'rules',
  'authz',
  'baseline',
  'reporter',
  'console',
  'html',
  'sarif',
  'junit',
  'schemas',
  'init',
  'app',
  'prototype',
  'deps',
  'release',
];
export const MAX_LENGTH = 72;

const HEADER = /^([a-z]+)(?:\(([^()]*)\))?(!)?: (.*)$/;

/**
 * Returns the problems found in a pull request title; an empty list means the title is valid.
 * @param {string} title
 * @returns {string[]}
 */
export function checkPrTitle(title) {
  /** @type {string[]} */
  const problems = [];
  if ([...title].length > MAX_LENGTH) {
    problems.push(`is ${[...title].length} characters long; the limit is ${MAX_LENGTH}`);
  }
  const match = HEADER.exec(title);
  if (!match) {
    problems.push('does not match "<type>(<scope>)!: <subject>" (scope and "!" are optional)');
    return problems;
  }
  const [, type = '', scope, , subject = ''] = match;
  if (!TYPES.includes(type)) {
    problems.push(`has unknown type "${type}"; use one of: ${TYPES.join(', ')}`);
  }
  if (scope !== undefined && !SCOPES.includes(scope)) {
    problems.push(`has unknown scope "${scope}"; use one of: ${SCOPES.join(', ')}`);
  }
  if (subject.trim() === '') {
    problems.push('has an empty subject');
  } else {
    if (subject !== subject.trim()) {
      problems.push('has leading or trailing whitespace in the subject');
    }
    // Dependabot always writes "Bump ..." with a capital letter and has no option to change it.
    const dependabot = scope === 'deps' && subject.startsWith('Bump ');
    if (!dependabot && !/^[a-z0-9`]/.test(subject)) {
      problems.push('subject must start with a lowercase letter after the colon');
    }
    if (subject.trimEnd().endsWith('.')) {
      problems.push('subject must not end with a period');
    }
  }
  return problems;
}

function main() {
  const title = process.argv[2] ?? process.env.PR_TITLE;
  if (title === undefined) {
    console.error('check-pr-title: pass the title as an argument or in PR_TITLE');
    process.exit(2);
  }
  const problems = checkPrTitle(title);
  if (problems.length > 0) {
    console.error(`check-pr-title: the title "${title}"`);
    for (const problem of problems) console.error(`  - ${problem}`);
    process.exit(1);
  }
  console.log(`check-pr-title: ok, "${title}"`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main();
