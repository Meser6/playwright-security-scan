// Recognized file layouts of the init wizard (11-REQ-08; after the perf package): each function returns the
// changed text, or null when the layout is not one it knows, so the caller prints a manual
// instruction instead. Pure.
import { PACKAGE_NAME } from '../constants.ts';
import {
  addImports,
  callParen,
  matchBracket,
  onlyTrailing,
  skipNonCode,
  statementEnds,
} from './scan.ts';

/** How playwright.config refers to the package config file (11-REQ-08). */
export interface SecConfigRef {
  /** Specifier of `import securityConfig from '…'`, e.g. "./pw-sec.config". */
  import: string;
  /** Expression in a CommonJS config, e.g. "require('./pw-sec.config').default". */
  require: string;
}

/** The reference to a package config file by its name and, for `.js`, its text (11-REQ-08). */
export function secConfigRef(file: string, text: string | null): SecConfigRef {
  if (/\.[cm]?ts$/u.test(file)) {
    const base = `./${file.replace(/\.[cm]?ts$/u, '')}`;
    return { import: base, require: `require('${base}').default` };
  }
  const cjs =
    file.endsWith('.cjs') || (file.endsWith('.js') && /\bmodule\.exports\b/u.test(text ?? ''));
  const path = `./${file}`;
  if (!cjs) return { import: path, require: `require('${path}').default` };
  return { import: path, require: `require('${file.endsWith('.js') ? path.slice(0, -3) : path}')` };
}

/** Index of the first top-level "," between `from` and `to`, or -1. */
function topLevelComma(text: string, from: number, to: number): number {
  let previous = '';
  for (let i = from; i < to;) {
    const skipped = skipNonCode(text, i, previous);
    if (skipped !== i) {
      i = skipped;
      continue;
    }
    const c = text[i] as string;
    if (c === '(' || c === '[' || c === '{') {
      const end = matchBracket(text, i);
      if (end === -1) return -1;
      i = end;
      previous = ')';
      continue;
    }
    if (c === ',') return i;
    if (!/\s/u.test(c)) previous = c;
    i += 1;
  }
  return -1;
}

/**
 * playwright.config wrapped in withSecurity() (03, chapter 3; 11-REQ-08):
 * `export default defineConfig({...})`, `export default {...}`, `export default withPerf(...)` or
 * the same with `module.exports =`, as the last statement of the file. With the perf package
 * withSecurity() goes outside withPerf() (01-REQ-09). `ref` refers to the package config file.
 */
export function wrapPlaywrightConfig(text: string, ref: SecConfigRef): string | null {
  const esm = [...text.matchAll(/^export\s+default\s+/gmu)];
  const cjs = [...text.matchAll(/^module\.exports\s*=\s*/gmu)];
  if (esm.length + cjs.length !== 1) return null;
  const isEsm = esm.length === 1;
  const match = (isEsm ? esm[0] : cjs[0]) as RegExpExecArray;
  const start = match.index + match[0].length;
  const rest = text.slice(start);
  let open: number;
  if (rest.startsWith('{')) open = start;
  else {
    const call = /^(defineConfig|withPerf)\s*/u.exec(rest);
    if (call === null) return null;
    open = callParen(text, start + (call[1] as string).length);
  }
  if (open === -1) return null;
  const end = matchBracket(text, open);
  if (end === -1 || !onlyTrailing(text, end)) return null;
  const value = text.slice(start, end);
  const config = isEsm ? 'securityConfig' : ref.require;
  const wrapped = `${text.slice(0, start)}withSecurity(${value}, ${config})${text.slice(end)}`;
  return addImports(
    wrapped,
    isEsm
      ? [
          `import { withSecurity } from '${PACKAGE_NAME}/config';`,
          `import securityConfig from '${ref.import}';`,
        ]
      : [`const { withSecurity } = require('${PACKAGE_NAME}/config');`],
  );
}

/**
 * The reverse order `withPerf(withSecurity(X, s), p)` turned into `withSecurity(withPerf(X, p), s)`
 * (01-REQ-09, 11-REQ-08): in perf mode withPerf() keeps only the reporters it knows, so the
 * security reporter would be dropped. Null when the file has no such call or another layout.
 */
export function fixPerfOrder(text: string): string | null {
  const m = /\bwithPerf\s*\(\s*withSecurity\s*\(/u.exec(text);
  if (m === null) return null;
  const perfOpen = text.indexOf('(', m.index);
  const secOpen = text.indexOf('(', perfOpen + 1);
  const perfEnd = matchBracket(text, perfOpen);
  const secEnd = matchBracket(text, secOpen);
  if (perfEnd === -1 || secEnd === -1) return null;
  const secComma = topLevelComma(text, secOpen + 1, secEnd - 1);
  const inner = text.slice(secOpen + 1, secComma === -1 ? secEnd - 1 : secComma).trim();
  const secArgs = secComma === -1 ? '' : text.slice(secComma, secEnd - 1).trimEnd();
  const perfRest = text.slice(secEnd, perfEnd - 1).trimEnd();
  if (perfRest !== '' && !perfRest.trimStart().startsWith(',')) return null;
  return `${text.slice(0, m.index)}withSecurity(withPerf(${inner}${perfRest})${secArgs})${text.slice(perfEnd)}`;
}

/**
 * The project's test object wrapped in withSecurityFixtures() (05, chapter 3):
 * `export const test = base.extend(...)` or `exports.test = base.test.extend(...)`, when it is the
 * only `.extend(` call of the file and the statement ends after it.
 */
export function wrapTestObject(text: string): string | null {
  const esm = /^export\s+const\s+test\s*=\s*([\w$.]+)\.extend\b/mu.exec(text);
  const cjs = /^(?:module\.)?exports\.test\s*=\s*([\w$.]+)\.extend\b/mu.exec(text);
  const match = esm ?? cjs;
  if (match === null || (esm !== null && cjs !== null)) return null;
  const exprStart = match.index + match[0].length - (match[1] as string).length - '.extend'.length;
  const open = callParen(text, match.index + match[0].length);
  if (open === -1) return null;
  const end = matchBracket(text, open);
  if (end === -1 || !statementEnds(text, end)) return null;
  const wrapped = `${text.slice(0, exprStart)}withSecurityFixtures(${text.slice(exprStart, end)})${text.slice(end)}`;
  return addImports(wrapped, [
    esm !== null
      ? `import { withSecurityFixtures } from '${PACKAGE_NAME}/fixture';`
      : `const { withSecurityFixtures } = require('${PACKAGE_NAME}/fixture');`,
  ]);
}

// Trailing globs that match everything inside a folder: "/*", "/**" and "/**" + "/*".
const FOLDER_GLOB = /\/(?:\*\*\/\*|\*\*|\*)$/u;

/**
 * Whether .gitignore already ignores `dir` or a folder that contains it (perf D-47, perf 04-AC-55), also
 * with a trailing glob (reports/ followed by * or **), unless a `!` line re-includes something
 * under it.
 */
export function ignores(gitignore: string, dir: string): boolean {
  const lines = gitignore.split(/\r?\n/u).map((line) => line.trim());
  const negated = lines
    .filter((line) => line.startsWith('!'))
    .map((line) => line.slice(1).replace(/^\//u, ''));
  return lines.some((line) => {
    if (line === '' || line.startsWith('#') || line.startsWith('!')) return false;
    const path = line.replace(/^\//u, '');
    const glob = FOLDER_GLOB.test(path);
    const entry = path.replace(FOLDER_GLOB, '').replace(/\/$/u, '');
    if (entry === '' || !(entry === dir || dir.startsWith(`${entry}/`))) return false;
    // Git cannot re-include a file under an excluded folder, but it can under a glob.
    return !glob || !negated.some((n) => n === entry || n.startsWith(`${entry}/`));
  });
}

/** .gitignore with `dir/` appended. */
export function addIgnore(gitignore: string | null, dir: string): string {
  if (gitignore === null || gitignore === '') return `${dir}/\n`;
  const nl = gitignore.includes('\r\n') ? '\r\n' : '\n';
  return `${gitignore}${gitignore.endsWith('\n') ? '' : nl}${dir}/${nl}`;
}

const ESM_PLAYWRIGHT_IMPORT = /^import\s*\{([^}]*)\}\s*from\s*(['"])@playwright\/test\2(\s*;)?/gmu;
const CJS_PLAYWRIGHT_REQUIRE =
  /^(const|let|var)\s*\{([^}]*)\}\s*=\s*require\s*\(\s*(['"])@playwright\/test\3\s*\)(\s*;)?/gmu;

/** Whether a named import (`test`, `test as setup`, `test: setup`) is the value `name`. */
function isName(item: string, name: string): boolean {
  return new RegExp(String.raw`^${name}\s*(?:(?:as|:)\s*[A-Za-z_$][\w$]*)?$`, 'u').test(item);
}

/**
 * A test file with `test` (and `expect`) imported from `<pkg>/test` instead of @playwright/test
 * (perf 04-D-49): `import { test, expect } from '@playwright/test'` or
 * `const { test, expect } = require('@playwright/test')`, the only statement that imports the
 * value test. Other names (types, devices) stay in an import of @playwright/test. Null for any
 * other layout.
 */
export function swapTestImport(text: string): string | null {
  const esm = [...text.matchAll(ESM_PLAYWRIGHT_IMPORT)];
  const cjs = [...text.matchAll(CJS_PLAYWRIGHT_REQUIRE)];
  const items = (m: RegExpExecArray, i: number): string[] =>
    (m[i] as string)
      .split(',')
      .map((s) => s.trim())
      .filter((s) => s !== '');
  const matches = [
    ...esm.map((m) => ({ m, list: items(m, 1), quote: m[2] as string, semi: m[3] ?? '' })),
    ...cjs.map((m) => ({ m, list: items(m, 2), quote: m[3] as string, semi: m[4] ?? '' })),
  ].filter((x) => x.list.some((item) => isName(item, 'test')));
  if (matches.length !== 1) return null;
  const { m, list, quote, semi } = matches[0] as (typeof matches)[number];
  const moved = list.filter((item) => isName(item, 'test') || isName(item, 'expect'));
  const kept = list.filter((item) => !moved.includes(item));
  const isEsm = esm.includes(m);
  const pkg = `${quote}${PACKAGE_NAME}/test${quote}`;
  const statement = (names: string[], from: string): string =>
    isEsm
      ? `import { ${names.join(', ')} } from ${from}${semi}`
      : `${m[1] as string} { ${names.join(', ')} } = require(${from})${semi}`;
  const playwright = `${quote}@playwright/test${quote}`;
  const replacement =
    kept.length === 0
      ? statement(moved, pkg)
      : `${statement(kept, playwright)}\n${statement(moved, pkg)}`;
  return `${text.slice(0, m.index)}${replacement}${text.slice(m.index + m[0].length)}`;
}
