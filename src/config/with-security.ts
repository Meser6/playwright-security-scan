// withSecurity(): the Playwright config wrapper (01, chapter 7; 03; 04).
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { extname, isAbsolute, resolve } from 'node:path';
import type { PlaywrightTestConfig, ReporterDescription } from '@playwright/test';
import { ConfigError, resolveConfig } from '../core/config/index.ts';
import type { ConfigIssue, SecurityConfigInput } from '../core/config/index.ts';
import { canonicalOrigin } from '../core/normalize/index.ts';
import type { Diagnostic } from '../core/types/index.ts';
import { CONFIG_ENV, readEnvLabel, readMode, RUN_ID_ENV, SALT_ENV } from '../mode/index.ts';
import { setRegistered } from '../registry/index.ts';
import { VERSION } from '../version.ts';
import { reporterEntryPath } from './reporter-path.ts';

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

/** Identity helper with types for pw-sec.config.ts (01, chapter 5). */
export function defineSecurityConfig(config: SecurityConfigInput): SecurityConfigInput {
  return config;
}

/** The package config from PW_SEC_CONFIG (03-REQ-04): a .json file or a module with a default export. */
function loadConfigFile(path: string): unknown {
  const file = isAbsolute(path) ? path : resolve(process.cwd(), path);
  try {
    if (extname(file).toLowerCase() === '.json') return JSON.parse(readFileSync(file, 'utf8'));
    const loaded: unknown = createRequire(resolve(process.cwd(), 'noop.js'))(file);
    if (typeof loaded === 'object' && loaded !== null && 'default' in loaded) {
      return (loaded as { default: unknown }).default;
    }
    return loaded;
  } catch (error) {
    const issue: ConfigIssue = {
      code: 'CONFIG_FILE_UNREADABLE',
      path: CONFIG_ENV,
      message: `${CONFIG_ENV}: cannot load ${JSON.stringify(path)}: ${error instanceof Error ? error.message : String(error)}`,
      hint: 'Point it to a .json file or a module whose default export is the config.',
    };
    throw new ConfigError([issue]);
  }
}

interface ProjectLike {
  name?: string;
  use?: { baseURL?: string };
}

/** Project names and baseURL origins of the scanned projects (05-REQ-03, 05-REQ-04). */
export function scannedProjects(
  config: PlaywrightTestConfig,
  projects: string[] | 'all',
): { names: string[]; baseOrigins: string[] } {
  const list: ProjectLike[] =
    config.projects !== undefined && config.projects.length > 0
      ? (config.projects as ProjectLike[])
      : [{ name: '' }];
  const names: string[] = [];
  const origins = new Set<string>();
  for (const project of list) {
    const name = project.name ?? '';
    if (projects !== 'all' && !projects.includes(name)) continue;
    names.push(name);
    const baseURL = project.use?.baseURL ?? config.use?.baseURL;
    const origin = baseURL === undefined ? null : canonicalOrigin(baseURL);
    if (origin !== null) origins.add(origin);
  }
  return { names, baseOrigins: [...origins].sort() };
}

function withReporter(config: PlaywrightTestConfig, path: string): ReporterDescription[] {
  const current = config.reporter;
  let list: ReporterDescription[];
  if (current === undefined) {
    // Playwright's own default when no reporter is configured.
    list = [[process.env.CI ? 'dot' : 'list']];
  } else if (typeof current === 'string') {
    list = [[current]];
  } else {
    list = [...current];
  }
  if (!list.some(([name]) => name === path)) list.push([path]);
  return list;
}

/**
 * `--reporter` on the command line replaces the reporters of the config, so the package reporter
 * would not run and a scan could never fail (pwexample pilot). Main process only.
 */
export function reporterFlagIssue(argv: readonly string[]): ConfigIssue | undefined {
  const start = argv.indexOf('test');
  const args = start < 0 ? [] : argv.slice(start + 1);
  const values: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i] ?? '';
    if (arg === '--reporter') values.push(args[i + 1] ?? '');
    else if (arg.startsWith('--reporter=')) values.push(arg.slice('--reporter='.length));
  }
  if (values.length === 0) return undefined;
  const names = values.flatMap((v) => v.split(','));
  if (names.some((n) => n.includes('playwright-security-scan/reporter'))) return undefined;
  return {
    code: 'RUN_REPORTER_FLAG',
    path: '--reporter',
    message: `--reporter=${values.join(',')} replaces the reporters of the Playwright config, so the security reporter would not run and the scan could not fail`,
    hint: `Add it to the flag: --reporter=${values.join(',')},playwright-security-scan/reporter (or drop --reporter).`,
  };
}

/** Main process only (TEST_WORKER_INDEX unset): one run id and one salt for every worker. */
function mainProcessSetup(): void {
  if (process.env.TEST_WORKER_INDEX !== undefined) return;
  if ((process.env[RUN_ID_ENV] ?? '') === '') {
    process.env[RUN_ID_ENV] =
      `${new Date().toISOString().replace(/[-:.]/g, '').slice(0, 15)}-${randomBytes(3).toString('hex')}`;
  }
  if ((process.env[SALT_ENV] ?? '') === '') process.env[SALT_ENV] = randomBytes(16).toString('hex');
}

/**
 * Wraps the Playwright config. Without PW_SEC_MODE it returns `config` itself (01-REQ-08, P-02).
 * In scan or baseline mode it validates the package config (03-REQ-02), registers it for the
 * reporter and the fixtures of this process (01-REQ-05) and returns a copy of `config` with the
 * package reporter appended (01-REQ-07); workers, retries and timeouts are not changed (D-04).
 * Invalid config or mode throws ConfigError before any test runs (04-AC-01).
 */
export function withSecurity<T extends PlaywrightTestConfig>(
  config: T,
  securityConfig?: SecurityConfigInput,
): T {
  const mode = readMode(process.env);
  if (!mode.ok) throw new ConfigError(mode.issues);
  if (mode.mode === null) return config;

  const fromEnv = (process.env[CONFIG_ENV] ?? '').trim();
  const input = fromEnv === '' ? securityConfig : (loadConfigFile(fromEnv) as SecurityConfigInput);
  const resolved = resolveConfig(input);
  const label = readEnvLabel(process.env);
  const issues = [...(resolved.ok ? [] : resolved.issues), ...(label.ok ? [] : label.issues)];
  if (!resolved.ok || !label.ok) throw new ConfigError(issues);
  // PW_SEC_ENV overrides run.env of the config (08-REQ-13).
  if (label.env !== undefined) resolved.config.run.env = label.env;

  if (process.env.TEST_WORKER_INDEX === undefined) {
    const flag = reporterFlagIssue(process.argv);
    if (flag !== undefined) throw new ConfigError([flag]);
  }
  mainProcessSetup();
  const { names, baseOrigins } = scannedProjects(config, resolved.config.scope.projects);
  const warnings: Diagnostic[] = [];
  if (
    (baseOrigins.length === 0 || !resolved.config.scope.includeBaseURL) &&
    resolved.config.scope.origins.length === 0
  ) {
    warnings.push({
      code: 'SCOPE_EMPTY',
      level: 'warn',
      message: 'scope: no origin is in scope; set `use.baseURL` or `scope.origins`',
    });
  }
  if (
    resolved.config.scope.includeBaseURL &&
    baseOrigins.some((origin) => LOCAL_HOSTS.has(new URL(origin).hostname))
  ) {
    warnings.push({
      code: 'LOCAL_ORIGIN',
      level: 'info',
      message: 'local origin: transport rules are advisory',
    });
  }

  setRegistered({
    config: resolved.config,
    mode: mode.mode,
    runId: process.env[RUN_ID_ENV] ?? '',
    salt: process.env[SALT_ENV] ?? '',
    pkgVersion: VERSION,
    baseOrigins,
    scannedProjects: names,
    configPassed: input !== undefined,
    warnings,
  });
  return { ...config, reporter: withReporter(config, reporterEntryPath()) };
}
