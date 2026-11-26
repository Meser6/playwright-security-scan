// Reads the project files the init detection needs (11-REQ-07): root files and the source files
// of the whole project, not only testDir: fixtures modules and page objects often sit next to the
// test directory. Nothing is imported or executed. Copied from the perf package (same author).
import { PACKAGE_NAME, REPORT_DIR } from '../constants.ts';
import type { CliHost } from '../host.ts';
import {
  INSTALLED_PLAYWRIGHT,
  LOCKFILES,
  SEC_CONFIG_NAMES,
  PLAYWRIGHT_CONFIG_NAMES,
  SOURCE_FILE,
  testDirsOf,
} from './detect.ts';
import {
  candidatePaths,
  importSpecifiers,
  normalizePath,
  packageName,
  relativePath,
  workspaceKey,
} from './imports.ts';

const ROOT_FILES = new Set([
  'package.json',
  'tsconfig.json',
  '.gitignore',
  ...PLAYWRIGHT_CONFIG_NAMES,
  ...SEC_CONFIG_NAMES,
]);
const SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  'coverage',
  'test-results',
  'playwright-report',
  'blob-report',
]);
const MAX_DEPTH = 8;
const MAX_FILES = 3000;

/** Most playwright.config files listed when the directory has none (perf 04-REQ-73). */
const MAX_CONFIGS = 20;

/**
 * playwright.config files in the subdirectories of `root`, at most 3 levels deep, without
 * node_modules and hidden directories (perf 04-REQ-73), as "/"-separated relative paths.
 */
export async function findPlaywrightConfigs(host: CliHost, root: string): Promise<string[]> {
  const found: string[] = [];
  let level = [''];
  for (let depth = 1; depth <= 3 && found.length < MAX_CONFIGS; depth += 1) {
    const next: string[] = [];
    for (const rel of level) {
      for (const entry of await host.listDir(rel === '' ? root : host.paths.join(root, rel))) {
        if (!entry.directory || entry.name === 'node_modules' || entry.name.startsWith('.'))
          continue;
        const dir = rel === '' ? entry.name : `${rel}/${entry.name}`;
        next.push(dir);
        const names = new Set((await host.listDir(host.paths.join(root, dir))).map((e) => e.name));
        const config = PLAYWRIGHT_CONFIG_NAMES.find((name) => names.has(name));
        if (config !== undefined && found.length < MAX_CONFIGS) found.push(`${dir}/${config}`);
      }
    }
    level = next;
  }
  return found.sort();
}

/** Project files relative to `root` with "/" separators, as detectProject() takes them. */
export async function readProjectFiles(host: CliHost, root: string): Promise<Map<string, string>> {
  const files = new Map<string, string>();
  const join = (rel: string): string => host.paths.join(root, rel);
  const read = async (rel: string): Promise<void> => {
    const text = await host.readText(join(rel));
    if (text !== null) files.set(rel, text);
  };

  for (const entry of await host.listDir(root)) {
    if (entry.directory) continue;
    if (Object.hasOwn(LOCKFILES, entry.name)) files.set(entry.name, '');
    else if (ROOT_FILES.has(entry.name)) await read(entry.name);
  }

  const playwright = host.resolvePlaywright(root);
  if (playwright !== null)
    files.set(INSTALLED_PLAYWRIGHT, JSON.stringify({ version: playwright.version }));

  const config = PLAYWRIGHT_CONFIG_NAMES.find((name) => files.has(name));
  if (config === undefined) return files;
  let count = 0;
  /** Nested repositories (git submodules): skipped unless a source imports from them (perf 04-D-49). */
  const repos: string[] = [];
  const walk = async (rel: string, depth: number): Promise<void> => {
    if (depth > MAX_DEPTH || rel.split('/').includes('..')) return;
    const entries = await host.listDir(rel === '.' ? root : join(rel));
    if (depth > 0 && entries.some((e) => e.name === '.git')) {
      repos.push(rel);
      return;
    }
    for (const entry of entries) {
      if (count >= MAX_FILES) return;
      const path = rel === '.' ? entry.name : `${rel}/${entry.name}`;
      if (entry.directory) {
        const skip = SKIP_DIRS.has(entry.name) || entry.name.startsWith('.') || path === REPORT_DIR;
        if (!skip) await walk(path, depth + 1);
      } else if (SOURCE_FILE.test(entry.name) && !files.has(path)) {
        count += 1;
        await read(path);
      }
    }
  };
  // The test directories first, so the file limit never hides them in a large project.
  for (const dir of testDirsOf(files.get(config) as string)) await walk(dir, 0);
  await walk('.', 0);
  await readImportedFromRepos(files, repos, read);
  await readWorkspaceEntries(host, root, files);
  return files;
}

/** Sources read by the walk, without node_modules keys. */
function sources(files: ReadonlyMap<string, string>): [string, string][] {
  return [...files].filter(([path]) => SOURCE_FILE.test(path) && !path.startsWith('node_modules/'));
}

/** Files of skipped nested repositories that a source imports with a relative path (perf 04-D-49). */
async function readImportedFromRepos(
  files: Map<string, string>,
  repos: readonly string[],
  read: (rel: string) => Promise<void>,
): Promise<void> {
  if (repos.length === 0) return;
  for (const [path, text] of sources(files)) {
    for (const specifier of importSpecifiers(text)) {
      if (!specifier.startsWith('.')) continue;
      const target = normalizePath(`${path.split('/').slice(0, -1).join('/')}/${specifier}`);
      if (!repos.some((repo) => target === repo || target.startsWith(`${repo}/`))) continue;
      for (const candidate of candidatePaths(target)) {
        if (files.has(candidate)) break;
        await read(candidate);
        if (files.has(candidate)) break;
      }
    }
  }
}

/** Most workspace packages followed (perf 04-D-49). */
const MAX_PACKAGES = 50;

/** Entry files of a package.json, in lookup order. */
function packageEntries(manifest: string | null): string[] {
  let pkg: Record<string, unknown> = {};
  try {
    const value: unknown = JSON.parse(manifest ?? '{}');
    if (typeof value === 'object' && value !== null) pkg = value as Record<string, unknown>;
  } catch {
    // A broken package.json: only the usual index files.
  }
  const found: string[] = [];
  const add = (value: unknown): void => {
    if (typeof value === 'string') found.push(value);
    else if (typeof value === 'object' && value !== null) {
      const conditions = value as Record<string, unknown>;
      for (const key of ['.', 'types', 'import', 'require', 'default']) add(conditions[key]);
    }
  };
  add(pkg['exports']);
  for (const key of ['types', 'module', 'main']) add(pkg[key]);
  found.push('src/index', 'index');
  return [...new Set(found.map((entry) => normalizePath(entry)))];
}

/**
 * Entry files of the workspace packages the sources import by name (perf 04-REQ-67, perf 04-D-49):
 * `node_modules/<name>` that resolves outside any node_modules folder (a workspace link, not an
 * installed package). The entry is stored under its path relative to `root` (it may start with
 * "../"), and workspaceKey(name) points to it.
 */
async function readWorkspaceEntries(
  host: CliHost,
  root: string,
  files: Map<string, string>,
): Promise<void> {
  const names = new Set<string>();
  for (const [, text] of sources(files)) {
    for (const specifier of importSpecifiers(text)) {
      const name = packageName(specifier);
      if (name !== null && !name.startsWith('@playwright/') && name !== PACKAGE_NAME)
        names.add(name);
    }
  }
  const realRoot = (await host.realPath(root)) ?? root;
  for (const name of [...names].sort().slice(0, MAX_PACKAGES)) {
    const dir = await host.realPath(host.paths.join(root, `node_modules/${name}`));
    if (dir === null || /[\\/]node_modules[\\/]/u.test(`${dir}/`)) continue;
    const manifest = await host.readText(host.paths.join(dir, 'package.json'));
    for (const entry of packageEntries(manifest).flatMap(candidatePaths)) {
      const text = await host.readText(host.paths.join(dir, entry));
      if (text === null || !SOURCE_FILE.test(entry)) continue;
      const key = relativePath(realRoot, host.paths.join(dir, entry)).replaceAll('\\', '/');
      files.set(key, text);
      files.set(workspaceKey(name), key);
      break;
    }
  }
}
