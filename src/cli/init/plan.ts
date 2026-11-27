// The change plan of the init wizard (perf 04-REQ-38 step 7, perf 04-REQ-39, perf 04-REQ-40, perf 04-REQ-42,
// perf 04-REQ-67): file changes for recognized layouts, manual instructions (INIT_MANUAL_STEP) for
// everything else. Test files are never changed: only a fixtures module is wrapped, otherwise the
// wizard shows the red box of INIT_TEST_OBJECT_MANUAL. package.json is never changed (perf D-35).
// Idempotent: a project that already has a change gets no second one. Pure.
import { PACKAGE_NAME, REPORT_DIR } from '../constants.ts';
import type { CliIssue } from '../constants.ts';
import { EXTEND_CALL, SEC_CONFIG_NAMES, SOURCE_FILE } from './detect.ts';
import { importSpecifiers, resolveImport, tsconfigAliases, workspaceKey } from './imports.ts';
import type { ProjectInfo } from './detect.ts';
import { translator } from './messages.ts';
import type { Translate, WizardLanguage } from './messages.ts';
import { renderSecConfig, ts } from './sec-config.ts';
import type { ConfigFormat, InitAnswers } from './sec-config.ts';
import {
  addIgnore,
  fixPerfOrder,
  ignores,
  secConfigRef,
  swapTestImport,
  wrapPlaywrightConfig,
  wrapTestObject,
} from './patterns.ts';
import type { SecConfigRef } from './patterns.ts';

export interface FileChange {
  path: string;
  kind: 'create' | 'modify';
  before: string | null;
  after: string;
}

/** The red box of 04-REQ-67: the test object could not be wrapped without changing test files. */
export interface TestObjectBox {
  /**
   * Files with `.extend(` (candidates for the fixtures module) and fixtures modules of workspace
   * packages, the most imported by test files first (perf 04-D-49).
   */
  extendFiles: string[];
  /** Test files that import each of extendFiles (perf 04-D-49). */
  importedBy: Record<string, number>;
  /** extendFiles in workspace packages: path → package name (perf 04-D-49). */
  workspace: Record<string, string>;
  /** Number of files that import from @playwright/test. */
  importingFiles: number;
}

export interface InitPlan {
  changes: FileChange[];
  manualSteps: CliIssue[];
  /** Set when nothing would be scanned until the user wraps the test object (11-REQ-08). */
  testObject: TestObjectBox | null;
  /**
   * Tests that import test straight from @playwright/test and no fixtures module (perf 04-D-49): the
   * import changes in `paths` (part of `changes`); the red box `box` applies unless every one of
   * them is applied.
   */
  importSwap: { paths: string[]; box: TestObjectBox } | null;
}

/**
 * The package config file the wizard writes (11-REQ-08): pw-sec.config.ts in a TypeScript project;
 * in a JavaScript project a file in the module system of playwright.config, `.js` when that system
 * is the package default, else `.mjs`/`.cjs`.
 */
export function secConfigFile(info: ProjectInfo): { path: string; format: ConfigFormat } {
  if (info.typescript) return { path: 'pw-sec.config.ts', format: 'ts' };
  const format = info.moduleType;
  const ext = format === info.packageModule ? 'js' : format === 'esm' ? 'mjs' : 'cjs';
  return { path: `pw-sec.config.${ext}`, format };
}

/** The package config file playwright.config refers to: the existing one, else the new one. */
function secConfigReference(info: ProjectInfo, answers: InitAnswers): SecConfigRef {
  const existing = info.existing.secConfig;
  if (existing !== null) return secConfigRef(existing, info.files.get(existing) ?? null);
  const file = secConfigFile(info);
  return secConfigRef(file.path, renderSecConfig(answers, file.format));
}

function manual(message: string, hint: string): CliIssue {
  return { code: 'INIT_MANUAL_STEP', message, hint };
}

function change(info: ProjectInfo, path: string, after: string): FileChange | null {
  const before = info.files.get(path) ?? null;
  if (before === after) return null;
  return { path, kind: before === null ? 'create' : 'modify', before, after };
}

const CONFIG_HINT = (t: Translate, path: string, ref: SecConfigRef): string =>
  [
    t('configHintIntro'),
    `  import { withSecurity } from '${PACKAGE_NAME}/config';`,
    `  import securityConfig from '${ref.import}';`,
    `  export default withSecurity(otherWrapper(defineConfig({ ... })), securityConfig);`,
    t('configHintCjs', { path, call: `withSecurity(config, ${ref.require})` }),
  ].join('\n');

function planSecConfig(
  info: ProjectInfo,
  answers: InitAnswers,
  plan: InitPlan,
  t: Translate,
): void {
  const existing = info.existing.secConfig;
  const file = secConfigFile(info);
  // withSecurity() is there already without a config file: a new file would not be used.
  if (existing === null && info.existing.wrappedConfig) return;
  if (existing === null) {
    const c = change(info, file.path, renderSecConfig(answers, file.format));
    if (c !== null) plan.changes.push(c);
    return;
  }
  // An existing config is never rewritten (11-REQ-08): the answers that differ go to a manual step.
  const values: string[] = [];
  if (answers.preset !== 'recommended') values.push(`rules.preset = ${ts(answers.preset)}`);
  if (answers.minSeverity !== 'medium')
    values.push(`gate.minSeverity = ${ts(answers.minSeverity)}`);
  if (answers.origins.length > 0) values.push(`scope.origins = ${ts(answers.origins)}`);
  if (answers.authzOrigins !== undefined && answers.authzOrigins.length > 0) {
    values.push(`authz = { enabled: true, allowedOrigins: ${ts(answers.authzOrigins)} }`);
  }
  if (values.length > 0) {
    plan.manualSteps.push(
      manual(
        t('manualSecConfigKept', { file: existing }),
        `${t('manualSecConfigHint')}\n${values.map((v) => `  ${v}`).join('\n')}`,
      ),
    );
  }
}

function planPlaywrightConfig(
  info: ProjectInfo,
  answers: InitAnswers,
  plan: InitPlan,
  t: Translate,
): void {
  const config = info.playwrightConfig;
  if (config === null) return;
  if (info.existing.wrappedConfig) {
    // withSecurity() inside withPerf(): perf mode would drop the reporter (01-REQ-09).
    const fixed = fixPerfOrder(config.text);
    if (fixed !== null)
      plan.changes.push({ path: config.path, kind: 'modify', before: config.text, after: fixed });
    return;
  }
  const existing = info.existing.secConfig;
  if (existing !== null && existing.endsWith('.json')) {
    const json = `./${existing}`;
    plan.manualSteps.push(
      manual(
        t('manualConfigJson', { config: config.path, file: existing }),
        CONFIG_HINT(t, config.path, { import: json, require: `require('${json}')` }),
      ),
    );
    return;
  }
  const ref = secConfigReference(info, answers);
  const after = wrapPlaywrightConfig(config.text, ref);
  if (after === null) {
    plan.manualSteps.push(
      manual(t('manualConfigPattern', { config: config.path }), CONFIG_HINT(t, config.path, ref)),
    );
    return;
  }
  plan.changes.push({ path: config.path, kind: 'modify', before: config.text, after });
}

/** A test call with a title at the start of a line: the file is a test file, not a module. */
const TEST_CALL =
  /^\s*(?:test|it)(?:\.(?:describe|only|skip|fixme|fail|serial|parallel|step)(?:\.\w+)?)?\s*\(\s*['"`]/mu;

/** Named imports from @playwright/test: `import { … } from` or `const { … } = require(`. */
const PLAYWRIGHT_TEST_NAMES =
  /\bimport\s*\{([^}]*)\}\s*from\s*(['"])@playwright\/test\2|\{([^}]*)\}\s*=\s*require\s*\(\s*(['"])@playwright\/test\4\s*\)/gu;

/**
 * A test file that takes `test` from @playwright/test: it imports the value `test` (alone or
 * renamed, e.g. `test as setup`) and is named `*.spec.*`/`*.test.*` or calls it with a title at
 * the start of a line. Page objects (`type Page`, `test.step`) and fixtures modules are not
 * counted (perf 04-REQ-72).
 */
function isPlaywrightTestFile(path: string, source: string): boolean {
  const aliases: string[] = [];
  if (/\brequire\s*\(\s*(['"])@playwright\/test\1\s*\)\s*\.test\b/u.test(source))
    aliases.push('test');
  for (const m of source.matchAll(PLAYWRIGHT_TEST_NAMES)) {
    for (const name of (m[1] ?? m[3] ?? '').split(',')) {
      const alias = /^\s*test\s*(?:(?:as|:)\s*([A-Za-z_$][\w$]*))?\s*$/u.exec(name);
      if (alias !== null) aliases.push(alias[1] ?? 'test');
    }
  }
  if (aliases.length > 0 && /\.(?:spec|test)\.[cm]?[jt]sx?$/u.test(path)) return true;
  return aliases.some((alias) =>
    new RegExp(
      String.raw`^\s*${alias.replaceAll('$', '\\$')}(?:\.\w+)*\s*\(\s*['"\x60]`,
      'mu',
    ).test(source),
  );
}

/** A setup or teardown file (`auth.setup.ts`, `test as setup`): not a measured test. */
function isSetupFile(path: string, source: string): boolean {
  if (/\.(?:setup|teardown)\.[cm]?[jt]sx?$/u.test(path)) return true;
  return /\btest\s+as\s+(?:setup|teardown)\b|\btest\s*:\s*(?:setup|teardown)\b/u.test(source);
}

/** Source files that are test files: `*.spec.*`/`*.test.*` or a test call at a line start. */
function testFiles(info: ProjectInfo): string[] {
  return [...info.files.keys()].filter(
    (path) =>
      SOURCE_FILE.test(path) &&
      !path.startsWith('node_modules/') &&
      !path.startsWith('../') &&
      (/\.(?:spec|test)\.[cm]?[jt]sx?$/u.test(path) || TEST_CALL.test(info.files.get(path) ?? '')),
  );
}

/**
 * Fixtures modules of workspace packages the tests import by name (perf 04-D-49): the package entry
 * file with exactly one `.extend(` that exports test, as in perf 04-REQ-67. Never changed by the
 * wizard (another package), only named in the red box.
 */
function workspaceFixtures(info: ProjectInfo): Record<string, string> {
  const found: Record<string, string> = {};
  const prefix = 'node_modules/';
  for (const [key, path] of info.files) {
    const name = key.startsWith(prefix) ? key.slice(prefix.length, key.lastIndexOf('/')) : '';
    if (key !== workspaceKey(name)) continue;
    const text = info.files.get(path) ?? '';
    if ([...text.matchAll(EXTEND_CALL)].length === 1 && wrapTestObject(text) !== null)
      found[path] = name;
  }
  return found;
}

/** How many test files import each of `targets` (perf 04-D-49). */
function importCounts(info: ProjectInfo, targets: readonly string[]): Record<string, number> {
  const aliases = tsconfigAliases(info.files.get('tsconfig.json'));
  const counts: Record<string, number> = Object.fromEntries(targets.map((t) => [t, 0]));
  for (const file of testFiles(info)) {
    const seen = new Set<string>();
    for (const specifier of importSpecifiers(info.files.get(file) ?? '')) {
      const target = resolveImport(file, specifier, info.files, aliases);
      if (target !== null && target in counts && !seen.has(target)) {
        seen.add(target);
        counts[target] = (counts[target] as number) + 1;
      }
    }
  }
  return counts;
}

/**
 * @playwright/test as a whole: a namespace or default import, or `require()` of the module
 * object; the import of such a file cannot be changed by name (perf 04-D-49).
 */
const OPAQUE_PLAYWRIGHT_IMPORT =
  /\bimport\s+(?:\*\s*as\s+[\w$]+|[\w$]+)\s*(?:,[^;]*?)?\bfrom\s*(['"])@playwright\/test\1|\b(?:const|let|var)\s+[\w$]+\s*=\s*require\s*\(\s*(['"])@playwright\/test\2\s*\)|\brequire\s*\(\s*(['"])@playwright\/test\3\s*\)\s*\.\s*test\b/u;

/** Test files (not setup files) that take `test` straight from @playwright/test. */
function directTestFiles(info: ProjectInfo): string[] {
  const text = (path: string): string => info.files.get(path) ?? '';
  return info.filesImportingPlaywrightTest.filter(
    (p) => isPlaywrightTestFile(p, text(p)) && !isSetupFile(p, text(p)),
  );
}

function planTestObject(info: ProjectInfo, plan: InitPlan, t: Translate): void {
  const text = (path: string): string => info.files.get(path) ?? '';
  const direct = directTestFiles(info);
  /** The yellow warning of 04-D-49: some tests are still not measured. */
  const warnDirect = (module: string | null): void => {
    if (direct.length === 0) return;
    plan.manualSteps.push(
      manual(
        t('manualDirectImports', { count: direct.length, files: direct.join(', ') }),
        [
          t(module === null ? 'manualDirectImportsHint' : 'manualDirectImportsModuleHint', {
            module: module ?? '',
          }),
          `  import { test, expect } from '${PACKAGE_NAME}/test';`,
        ].join('\n'),
      ),
    );
  };
  if (info.existing.wrappedTest) {
    warnDirect(null);
    return;
  }
  const extendFiles = info.filesWithExtend;
  const merges = info.filesImportingPlaywrightTest.filter((p) =>
    /\bmergeTests\s*\(/u.test(text(p)),
  );
  const only = extendFiles.length === 1 && merges.length === 0 ? (extendFiles[0] as string) : null;
  const after =
    only !== null &&
    [...text(only).matchAll(EXTEND_CALL)].length === 1 &&
    !TEST_CALL.test(text(only))
      ? wrapTestObject(text(only))
      : null;
  if (only !== null && after !== null) {
    plan.changes.push({ path: only, kind: 'modify', before: text(only), after });
    warnDirect(only);
    return;
  }
  // Only steps measured: the reporter records them without the perf fixture (06), so something
  // is measured and there is no red box (v4 D5).
  const workspace = workspaceFixtures(info);
  const candidates = [...new Set([...extendFiles, ...merges, ...Object.keys(workspace)])];
  const importedBy = importCounts(info, candidates);
  const box: TestObjectBox = {
    extendFiles: candidates.sort(
      (a, b) =>
        (importedBy[b] as number) - (importedBy[a] as number) || (a < b ? -1 : a > b ? 1 : 0),
    ),
    importedBy,
    workspace,
    // Test files only: page objects and fixtures modules import @playwright/test too (perf 04-REQ-72).
    importingFiles: info.filesImportingPlaywrightTest.filter((p) =>
      isPlaywrightTestFile(p, text(p)),
    ).length,
  };
  // Tests that import test straight from @playwright/test and no fixtures module: the import
  // changes as diffs (perf 04-D-49). One file the wizard cannot change keeps the red box alone.
  const opaque = testFiles(info).some(
    (p) => !isSetupFile(p, text(p)) && OPAQUE_PLAYWRIGHT_IMPORT.test(text(p)),
  );
  const swaps =
    candidates.length === 0 && !opaque ? direct.map((p) => [p, swapTestImport(text(p))]) : [];
  if (swaps.length > 0 && swaps.every(([, a]) => a !== null)) {
    for (const [path, swapped] of swaps)
      plan.changes.push({
        path: path as string,
        kind: 'modify',
        before: text(path as string),
        after: swapped as string,
      });
    plan.importSwap = { paths: direct, box };
    return;
  }
  plan.testObject = box;
}

/** Contexts of request.newContext() that are not tracked (perf 04-REQ-74): a manual step. */
function planRequestContexts(info: ProjectInfo, plan: InitPlan, t: Translate): void {
  const files = info.untrackedContextFiles;
  if (files.length === 0) return;
  plan.manualSteps.push(
    manual(
      t('manualNewContext', { count: files.length, files: files.join(', ') }),
      [
        t('manualNewContextHint'),
        `  import { trackRequestContext } from '${PACKAGE_NAME}/fixture';`,
        '  const ctx = await request.newContext();',
        '  trackRequestContext(ctx);',
      ].join('\n'),
    ),
  );
}

/** "yes" in step 4a (18-REQ-22): what the wizard cannot write for the authorization tests. */
function planAuthz(info: ProjectInfo, answers: InitAnswers, plan: InitPlan, t: Translate): void {
  const origins = answers.authzOrigins;
  if (origins === undefined) return;
  if (origins.length === 0) {
    plan.manualSteps.push(
      manual(
        t('manualAuthzOrigins'),
        [
          t('manualAuthzOriginsHint'),
          "  authz: { enabled: true, allowedOrigins: ['https://staging.example.com'] },",
        ].join('\n'),
      ),
    );
    return;
  }
  // A new config maps no project to a shared role: no role has a pair for the IDOR test (14-REQ-12).
  const first = info.roleProjects[0] ?? 'customer';
  plan.manualSteps.push(
    manual(
      t('manualAuthzUser'),
      [
        t('manualAuthzUserHint'),
        `  // auth.setup.ts: sign in a second user and save .auth/${first}2.json`,
        `  // playwright.config: { name: '${first}2', dependencies: ['setup'], use: { storageState: '.auth/${first}2.json' } }`,
        `  // pw-sec.config: authz: { roles: { '${first}2': { role: '${first}' } } }`,
      ].join('\n'),
    ),
  );
}

function planGitignore(info: ProjectInfo, plan: InitPlan): void {
  const dir = REPORT_DIR;
  const current = info.files.get('.gitignore') ?? null;
  if (current !== null && ignores(current, dir)) return;
  const c = change(info, '.gitignore', addIgnore(current, dir));
  if (c !== null) plan.changes.push(c);
}

/**
 * Pure plan of the init changes; unrecognized layouts give manual steps (perf 04-REQ-39) in the wizard
 * language (perf 04-REQ-43). The file changes do not depend on the language.
 */
export function planInitChanges(
  info: ProjectInfo,
  answers: InitAnswers,
  lang: WizardLanguage = 'en',
): InitPlan {
  const t = translator(lang);
  const plan: InitPlan = { changes: [], manualSteps: [], testObject: null, importSwap: null };
  planSecConfig(info, answers, plan, t);
  planPlaywrightConfig(info, answers, plan, t);
  planTestObject(info, plan, t);
  planRequestContexts(info, plan, t);
  planAuthz(info, answers, plan, t);
  planGitignore(info, plan);
  return plan;
}

/** Whether `path` is an existing package config, which needs its own confirmation (perf 04-REQ-40). */
export function isProtected(info: ProjectInfo, path: string): boolean {
  return SEC_CONFIG_NAMES.includes(path) && info.existing.secConfig === path;
}
