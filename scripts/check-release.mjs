#!/usr/bin/env node
// @ts-check
// Release preconditions (13-REQ-10), run by .github/workflows/release.yml
// before anything is published:
// - the tag is vX.Y.Z or vX.Y.Z-<next|beta|rc>.N and equals "version" of package.json and
//   create/package.json (both packages are released together, 11-REQ-02);
// - neither package.json has "private": true (flipping it is the owner's release step);
// - CHANGELOG.md has a "## [X.Y.Z]" section, whose text becomes the GitHub Release notes.
// Prints the npm dist-tag: "next" for a pre-release (-next.N, -beta.N, -rc.N), "latest" otherwise; a pre-release never
// goes to "latest".
//
// Usage: node scripts/check-release.mjs <tag> [--notes <file>]
//   --notes <file>  write the CHANGELOG section of the version to <file>
// No dependencies; Node built-ins only.
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-(?:next|beta|rc)\.(0|[1-9]\d*))?$/u;

/**
 * @typedef {{ ok: true, version: string, distTag: 'latest' | 'next', prerelease: boolean, notes: string }
 *   | { ok: false, problems: string[] }} ReleaseCheck
 */

/**
 * The text of the "## [version]" section of a Keep a Changelog file, without its heading;
 * null when there is none.
 * @param {string} changelog
 * @param {string} version
 * @returns {string | null}
 */
export function changelogSection(changelog, version) {
  const lines = changelog.replaceAll('\r\n', '\n').split('\n');
  const start = lines.findIndex((line) => line.startsWith(`## [${version}]`));
  if (start === -1) return null;
  const rest = lines.slice(start + 1);
  const end = rest.findIndex((line) => line.startsWith('## '));
  const body = (end === -1 ? rest : rest.slice(0, end))
    .filter((line) => !/^\[[^\]]+\]:\s/u.test(line))
    .join('\n')
    .trim();
  return body;
}

/**
 * @param {string} tag
 * @param {Record<string, any>} main package.json
 * @param {Record<string, any>} create create/package.json
 * @param {string} changelog CHANGELOG.md
 * @returns {ReleaseCheck}
 */
export function checkRelease(tag, main, create, changelog) {
  const problems = [];
  const version = tag.startsWith('v') ? tag.slice(1) : '';
  const match = VERSION.exec(version);
  if (match === null) {
    problems.push(
      `The tag "${tag}" is not vX.Y.Z or vX.Y.Z-<next|beta|rc>.N (pre-releases use the next dist-tag only).`,
    );
  }
  /** @type {[string, Record<string, any>][]} */
  const manifests = [
    ['package.json', main],
    ['create/package.json', create],
  ];
  for (const [label, pkg] of manifests) {
    if (pkg.version !== version) {
      problems.push(`${label}: version ${pkg.version} does not match the tag ${tag}.`);
    }
    if (pkg.private === true) {
      problems.push(`${label}: "private": true; the owner removes it before the first release.`);
    }
  }
  const notes = changelogSection(changelog, version);
  if (notes === null) {
    problems.push(`CHANGELOG.md has no "## [${version}]" section.`);
  } else if (notes === '') {
    problems.push(`CHANGELOG.md: the "## [${version}]" section is empty.`);
  }
  if (problems.length > 0 || match === null || notes === null) return { ok: false, problems };
  const prerelease = match[4] !== undefined;
  return { ok: true, version, distTag: prerelease ? 'next' : 'latest', prerelease, notes };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const root = join(dirname(fileURLToPath(import.meta.url)), '..');
  const [tag, ...rest] = process.argv.slice(2);
  if (tag === undefined) {
    console.error('Usage: node scripts/check-release.mjs <tag> [--notes <file>]');
    process.exit(2);
  }
  const read = (/** @type {string} */ path) => readFileSync(join(root, path), 'utf8');
  const result = checkRelease(
    tag,
    JSON.parse(read('package.json')),
    JSON.parse(read('create/package.json')),
    read('CHANGELOG.md'),
  );
  if (!result.ok) {
    for (const problem of result.problems) console.error(`error: ${problem}`);
    process.exit(1);
  }
  const notesIndex = rest.indexOf('--notes');
  const notesFile = notesIndex === -1 ? undefined : rest[notesIndex + 1];
  if (notesFile !== undefined) writeFileSync(notesFile, `${result.notes}\n`);
  console.log(result.distTag);
}
