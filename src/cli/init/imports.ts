// Text-only import resolution of the init wizard (perf 04-REQ-67, perf 04-REQ-72, perf 04-D-49): which project
// file a module specifier of a source file points to, so that the red box can say how many test
// files import each fixtures module. Relative specifiers, `compilerOptions.paths` of tsconfig.json
// and workspace packages (resolved by files.ts) are followed; nothing is imported or executed.
// Pure.

/** Extensions tried for a specifier without one, in TypeScript resolution order. */
const EXTENSIONS = ['.ts', '.tsx', '.mts', '.cts', '.js', '.jsx', '.mjs', '.cjs'];

/**
 * Key of the file map that holds the entry file of a workspace package (the project-relative
 * path, which may start with "../"); files.ts sets it for bare specifiers that resolve outside
 * node_modules (perf 04-D-49).
 */
export function workspaceKey(name: string): string {
  return `node_modules/${name}/.pw-sec-workspace-entry`;
}

/** Module specifiers of `from '…'`, `import '…'`, `import('…')` and `require('…')`. */
export function importSpecifiers(source: string): string[] {
  const found = new Set<string>();
  const re = /(?:\bfrom\s*|\brequire\s*\(\s*|\bimport\s*\(\s*|^\s*import\s*)(['"])([^'"\n]+)\1/gmu;
  for (const m of source.matchAll(re)) found.add(m[2] as string);
  return [...found];
}

/** "a/b/../c" → "a/c"; a leading ".." that cannot be removed stays. */
export function normalizePath(path: string): string {
  const out: string[] = [];
  for (const part of path.split('/')) {
    if (part === '' || part === '.') continue;
    if (part === '..' && out.length > 0 && out.at(-1) !== '..') out.pop();
    else out.push(part);
  }
  return out.join('/');
}

function dirOf(path: string): string {
  const i = path.lastIndexOf('/');
  return i === -1 ? '' : path.slice(0, i);
}

/** An alias of tsconfig.json `compilerOptions.paths`: "@fixtures/*" → ["tests/fixtures/*"]. */
export interface PathAlias {
  pattern: string;
  targets: string[];
}

/** Text of a JSON file with comments and trailing commas (tsconfig.json) as plain JSON. */
function stripJsonc(text: string): string {
  let out = '';
  for (let i = 0; i < text.length; i += 1) {
    const c = text[i] as string;
    if (c === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      out += text.slice(i, j + 1);
      i = j;
    } else if (c === '/' && text[i + 1] === '/') {
      const end = text.indexOf('\n', i);
      i = end === -1 ? text.length : end - 1;
    } else if (c === '/' && text[i + 1] === '*') {
      const end = text.indexOf('*/', i + 2);
      i = end === -1 ? text.length : end + 1;
    } else out += c;
  }
  return out.replace(/,(\s*[}\]])/gu, '$1');
}

/** The path aliases of a root tsconfig.json, relative to the project (empty when none). */
export function tsconfigAliases(text: string | undefined): PathAlias[] {
  if (text === undefined) return [];
  let json: unknown;
  try {
    json = JSON.parse(stripJsonc(text));
  } catch {
    return [];
  }
  const options = (json as { compilerOptions?: { baseUrl?: unknown; paths?: unknown } } | null)
    ?.compilerOptions;
  const paths = options?.paths;
  if (typeof paths !== 'object' || paths === null) return [];
  const base = typeof options?.baseUrl === 'string' ? options.baseUrl : '.';
  return Object.entries(paths as Record<string, unknown>)
    .filter((entry): entry is [string, string[]] => Array.isArray(entry[1]))
    .map(([pattern, targets]) => ({
      pattern,
      targets: targets
        .filter((t): t is string => typeof t === 'string')
        .map((t) => normalizePath(`${base}/${t}`)),
    }));
}

/** Files a path without or with an extension may mean, in lookup order (also `.js` → `.ts`). */
export function candidatePaths(path: string): string[] {
  const candidates = [path, ...EXTENSIONS.map((e) => `${path}${e}`)];
  if (/\.[cm]?jsx?$/u.test(path)) {
    const stem = path.replace(/\.([cm]?)js(x?)$/u, '');
    candidates.push(`${stem}.ts`, `${stem}.tsx`, `${stem}.mts`, `${stem}.cts`);
  }
  candidates.push(...EXTENSIONS.map((e) => `${path}/index${e}`));
  return candidates;
}

function existing(path: string, has: (path: string) => boolean): string | null {
  return candidatePaths(path).find((c) => has(c)) ?? null;
}

/** The package name of a bare specifier ("@a/b/c" → "@a/b", "x/y" → "x"), or null. */
export function packageName(specifier: string): string | null {
  if (specifier.startsWith('.') || specifier.startsWith('/') || specifier.includes(':'))
    return null;
  const parts = specifier.split('/');
  return specifier.startsWith('@')
    ? parts.length >= 2
      ? `${parts[0]}/${parts[1]}`
      : null
    : (parts[0] ?? null);
}

/** Path from directory `from` to `to` with "/" separators (both absolute, any separator). */
export function relativePath(from: string, to: string): string {
  const a = from.split(/[\\/]+/u).filter((p) => p !== '');
  const b = to.split(/[\\/]+/u).filter((p) => p !== '');
  let i = 0;
  while (i < a.length && i < b.length && a[i] === b[i]) i += 1;
  return [...a.slice(i).map(() => '..'), ...b.slice(i)].join('/');
}

/**
 * The project path of the file `specifier` in `from` points to, or null: relative paths, tsconfig
 * aliases and workspace packages (`node_modules/<name>` keys set by files.ts).
 */
export function resolveImport(
  from: string,
  specifier: string,
  files: ReadonlyMap<string, string>,
  aliases: readonly PathAlias[],
): string | null {
  const has = (path: string): boolean => files.has(path);
  if (specifier.startsWith('./') || specifier.startsWith('../')) {
    return existing(normalizePath(`${dirOf(from)}/${specifier}`), has);
  }
  for (const alias of aliases) {
    const star = alias.pattern.indexOf('*');
    let rest: string | null = null;
    if (star === -1) rest = alias.pattern === specifier ? '' : null;
    else {
      const prefix = alias.pattern.slice(0, star);
      const suffix = alias.pattern.slice(star + 1);
      if (specifier.startsWith(prefix) && specifier.endsWith(suffix))
        rest = specifier.slice(prefix.length, specifier.length - suffix.length);
    }
    if (rest === null) continue;
    for (const target of alias.targets) {
      const found = existing(normalizePath(target.replace('*', rest)), has);
      if (found !== null) return found;
    }
  }
  // The package entry only: a subpath import of a workspace package is not followed.
  const name = packageName(specifier);
  return name === null || name !== specifier ? null : (files.get(workspaceKey(name)) ?? null);
}
