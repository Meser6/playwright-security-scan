// Project analysis of the init wizard (11-REQ-07): text only. No user code is executed;
// playwright.config is read as text, never imported. Pure: the caller reads the files (files.ts)
// and passes them as a map of project-relative paths with "/". After the perf package.
import { CONFIG_FILE_BASENAME, CONFIG_FILE_EXTENSIONS, PACKAGE_NAME } from '../constants.ts';

export type PackageManager = 'npm' | 'pnpm' | 'yarn';

export interface ProjectInfo {
  playwrightConfig: { path: string; text: string } | null;
  playwrightVersion: string | null;
  packageManager: PackageManager;
  moduleType: 'esm' | 'cjs';
  /** The module system of a `.js` file in the package ("type" in package.json). */
  packageModule: 'esm' | 'cjs';
  /** playwright.config is TypeScript or tsconfig.json lies next to it (perf 04-REQ-46). */
  typescript: boolean;
  testDir: string;
  filesImportingPlaywrightTest: string[];
  filesWithExtend: string[];
  /** Scripts of package.json: name → command (perf 04-REQ-55). */
  scriptTexts: Record<string, string>;
  /** Origin of a `baseURL: '<literal>'` in playwright.config (11, step 4), or null. */
  baseOrigin: string | null;
  /** Other http(s) origins written in the sources, most frequent first, at most 10 (11, step 4). */
  foundOrigins: string[];
  /** Projects with `storageState: '<literal>'` in playwright.config: roles of step 4a (18-REQ-22). */
  roleProjects: string[];
  /** Source files with request.newContext( and no trackRequestContext (perf 04-REQ-74). */
  untrackedContextFiles: string[];
  existing: {
    /** pw-sec.config.* of the project. */
    secConfig: string | null;
    /** withSecurity( in playwright.config. */
    wrappedConfig: boolean;
    /** withPerf( in playwright.config: the perf package is set up (11-REQ-08). */
    perfConfig: boolean;
    /** withSecurityFixtures( or an import of <pkg>/test in a source file. */
    wrappedTest: boolean;
    scripts: string[];
  };
  /** The files detection read (the input map); the change plan works on their text. */
  files: ReadonlyMap<string, string>;
}

/** playwright.config file names, in the order they are looked up. */
export const PLAYWRIGHT_CONFIG_NAMES: readonly string[] = [
  'ts',
  'mts',
  'cts',
  'js',
  'mjs',
  'cjs',
].map((ext) => `playwright.config.${ext}`);

/** Package config file names (11-REQ-08). */
export const SEC_CONFIG_NAMES: readonly string[] = CONFIG_FILE_EXTENSIONS.map(
  (ext) => `${CONFIG_FILE_BASENAME}${ext}`,
);

/** Key of the installed @playwright/test manifest in the file map. */
export const INSTALLED_PLAYWRIGHT = 'node_modules/@playwright/test/package.json';

export const LOCKFILES: Readonly<Record<string, PackageManager>> = {
  'pnpm-lock.yaml': 'pnpm',
  'yarn.lock': 'yarn',
  'package-lock.json': 'npm',
};

export const SOURCE_FILE = /\.(?:[cm]?[jt]s|[jt]sx)$/u;
const IMPORTS_PLAYWRIGHT_TEST =
  /(?:\bfrom\s*|\brequire\s*\(\s*|\bimport\s*\(\s*|^\s*import\s*)(['"])@playwright\/test\1/mu;
/** A `.extend(` call other than `expect.extend(` (custom matchers). */
export const EXTEND_CALL = /(?<!\bexpect)\.extend\s*[<(]/gu;
/**
 * A fixture definition: `({ page }, use`, an option or a worker fixture. With an import of
 * @playwright/test it marks a `.extend(` file as a fixtures module, so that `.extend(` in
 * application code (e.g. zod schemas) found by the project-wide scan is not one (perf 04-REQ-72).
 */
const FIXTURE_SIGNATURE =
  /\(\s*\{[^{}]*\}\s*,\s*use\b|\boption\s*:\s*true\b|\bscope\s*:\s*['"]worker['"]/u;
/** `request.newContext(`, also `playwright.request.newContext(` (perf 04-REQ-74). */
const NEW_REQUEST_CONTEXT = /\brequest\s*\.\s*newContext\s*\(/u;
const WRAPPED_TEST = new RegExp(
  String.raw`\bwithSecurityFixtures\s*\(|(['"])${PACKAGE_NAME}/test\1`,
  'u',
);

/** Hosts of analytics, fonts and CDNs: never proposed as origins of the app (11, step 4). */
const THIRD_PARTY =
  /(?:^|\.)(?:google-analytics\.com|googletagmanager\.com|googleapis\.com|gstatic\.com|doubleclick\.net|facebook\.(?:com|net)|jsdelivr\.net|unpkg\.com|cdnjs\.cloudflare\.com|sentry\.io|hotjar\.com|segment\.(?:com|io)|w3\.org|example\.(?:com|org|net)|playwright\.dev|github\.com|npmjs\.(?:com|org))$/u;
const URL_LITERAL = /['"`](https?:\/\/[a-z0-9.-]+(?::\d+)?)(?=[/'"`?#])/giu;
const MAX_ORIGINS = 10;

/** `https://Host:443` → `https://host`; the default port is dropped. */
export function originOf(url: string): string | null {
  try {
    const u = new URL(url);
    return u.protocol === 'http:' || u.protocol === 'https:' ? u.origin : null;
  } catch {
    return null;
  }
}

/** Origins written in `texts`, without `base` and third parties, most frequent first. */
function originsIn(texts: readonly string[], base: string | null): string[] {
  const counts = new Map<string, number>();
  for (const text of texts) {
    for (const m of text.matchAll(URL_LITERAL)) {
      const origin = originOf(m[1] as string);
      if (origin === null || origin === base || THIRD_PARTY.test(new URL(origin).hostname))
        continue;
      counts.set(origin, (counts.get(origin) ?? 0) + 1);
    }
  }
  return [...counts]
    .sort(([a, x], [b, y]) => y - x || (a < b ? -1 : 1))
    .slice(0, MAX_ORIGINS)
    .map(([origin]) => origin);
}

/** testDir values written as string literals in playwright.config ("." when there is none). */
export function testDirsOf(configText: string): string[] {
  const dirs = [...configText.matchAll(/\btestDir\s*:\s*(['"`])([^'"`\n]+)\1/gu)].map((m) =>
    normalizeDir(m[2] as string),
  );
  return dirs.length === 0 ? ['.'] : [...new Set(dirs)];
}

function normalizeDir(dir: string): string {
  const clean = dir
    .replaceAll('\\', '/')
    .replace(/^\.\/+/u, '')
    .replace(/\/+$/u, '');
  return clean === '' ? '.' : clean;
}

function parseJson(text: string | undefined): Record<string, unknown> | null {
  if (text === undefined) return null;
  try {
    const value: unknown = JSON.parse(text);
    return typeof value === 'object' && value !== null && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

function stringField(obj: Record<string, unknown> | null, ...keys: string[]): string | null {
  let value: unknown = obj;
  for (const key of keys) {
    if (typeof value !== 'object' || value === null) return null;
    value = (value as Record<string, unknown>)[key];
  }
  return typeof value === 'string' ? value : null;
}

/** Version of @playwright/test: the installed one, else the version in the dependency range. */
function playwrightVersion(
  files: ReadonlyMap<string, string>,
  pkg: Record<string, unknown> | null,
): string | null {
  const installed = stringField(parseJson(files.get(INSTALLED_PLAYWRIGHT)), 'version');
  if (installed !== null) return installed;
  const range =
    stringField(pkg, 'devDependencies', '@playwright/test') ??
    stringField(pkg, 'dependencies', '@playwright/test');
  return range === null ? null : (/\d+\.\d+\.\d+/u.exec(range)?.[0] ?? null);
}

function packageManagerOf(
  files: ReadonlyMap<string, string>,
  pkg: Record<string, unknown> | null,
): PackageManager {
  for (const [file, manager] of Object.entries(LOCKFILES)) {
    if (files.has(file)) return manager;
  }
  const declared = /^(npm|pnpm|yarn)@/u.exec(stringField(pkg, 'packageManager') ?? '');
  return (declared?.[1] as PackageManager | undefined) ?? 'npm';
}

function sourceFiles(files: ReadonlyMap<string, string>, configPath: string | null): string[] {
  return [...files.keys()]
    .filter(
      (path) =>
        SOURCE_FILE.test(path) &&
        path !== configPath &&
        !path.startsWith('node_modules/') &&
        // Workspace package entries (files.ts) are outside the project: never changed.
        !path.startsWith('../') &&
        !path.includes('/node_modules/') &&
        !SEC_CONFIG_NAMES.includes(path),
    )
    .sort();
}

/**
 * Projects with a literal storageState (11-REQ-07, 18-REQ-22): the closest `name: '<x>'` before each
 * `storageState: '<path>'` in the same object, else the path.
 */
export function roleProjectsIn(configText: string): string[] {
  const out: string[] = [];
  for (const m of configText.matchAll(/\bstorageState\s*:\s*(['"`])([^'"`\n]+)\1/gu)) {
    const before = configText.slice(0, m.index);
    // The object of the project: the brace before its `use`.
    const objectStart = before.lastIndexOf('{', before.lastIndexOf('use'));
    const names = [
      ...before.slice(Math.max(0, objectStart)).matchAll(/\bname\s*:\s*(['"`])([^'"`\n]+)\1/gu),
    ];
    const name = names.at(-1)?.[2] ?? (m[2] as string);
    if (!out.includes(name)) out.push(name);
  }
  return out;
}

/** Text-only detection (perf 04-REQ-38 step 1, perf 04-D-18). */
export function detectProject(files: ReadonlyMap<string, string>): ProjectInfo {
  const configPath = PLAYWRIGHT_CONFIG_NAMES.find((name) => files.has(name)) ?? null;
  const configText = configPath === null ? '' : (files.get(configPath) as string);
  const pkg = parseJson(files.get('package.json'));
  const sources = sourceFiles(files, configPath);
  const text = (path: string): string => files.get(path) ?? '';

  const moduleType: 'esm' | 'cjs' =
    configPath?.endsWith('.mts') || configPath?.endsWith('.mjs')
      ? 'esm'
      : configPath?.endsWith('.cts') || configPath?.endsWith('.cjs')
        ? 'cjs'
        : pkg?.['type'] === 'module'
          ? 'esm'
          : 'cjs';

  const packageModule: 'esm' | 'cjs' = pkg?.['type'] === 'module' ? 'esm' : 'cjs';
  const baseLiteral = /\bbaseURL\s*:\s*(['"`])(https?:\/\/[^'"`\s]+)\1/u.exec(configText);
  const baseOrigin = baseLiteral === null ? null : originOf(baseLiteral[2] as string);
  const scripts = pkg?.['scripts'];
  return {
    playwrightConfig: configPath === null ? null : { path: configPath, text: configText },
    playwrightVersion: playwrightVersion(files, pkg),
    packageManager: packageManagerOf(files, pkg),
    moduleType,
    packageModule,
    typescript: configPath === null || /\.[cm]?ts$/u.test(configPath) || files.has('tsconfig.json'),
    testDir: testDirsOf(configText)[0] as string,
    filesImportingPlaywrightTest: sources.filter((p) => IMPORTS_PLAYWRIGHT_TEST.test(text(p))),
    filesWithExtend: sources.filter(
      (p) =>
        text(p).search(EXTEND_CALL) !== -1 &&
        (IMPORTS_PLAYWRIGHT_TEST.test(text(p)) || FIXTURE_SIGNATURE.test(text(p))),
    ),
    scriptTexts:
      typeof scripts === 'object' && scripts !== null
        ? Object.fromEntries(
            Object.entries(scripts).filter((e): e is [string, string] => typeof e[1] === 'string'),
          )
        : {},
    baseOrigin,
    foundOrigins: originsIn([configText, ...sources.map(text)], baseOrigin),
    roleProjects: roleProjectsIn(configText),
    untrackedContextFiles: sources.filter(
      (p) => NEW_REQUEST_CONTEXT.test(text(p)) && !text(p).includes('trackRequestContext'),
    ),
    existing: {
      secConfig: SEC_CONFIG_NAMES.find((name) => files.has(name)) ?? null,
      wrappedConfig: /\bwithSecurity\s*\(/u.test(configText),
      perfConfig: /\bwithPerf\s*\(/u.test(configText),
      wrappedTest: sources.some((p) => WRAPPED_TEST.test(text(p))),
      scripts: typeof scripts === 'object' && scripts !== null ? Object.keys(scripts).sort() : [],
    },
    files,
  };
}
