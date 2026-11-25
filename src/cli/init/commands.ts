// Run commands of the init wizard (11, chapters 4, 7 and 8): the test command C (the answer of
// step 6, by default the command of the detected package manager), the commands of every mode
// shown by the wizard (no CI jobs), and the runs and process of the wizard's check. Nothing is
// executed here. Pure. After the perf package; perf spec IDs are marked "perf".
import type { CliIssue, Result } from '../constants.ts';
import type { PackageManager } from './detect.ts';

export interface RunCommands {
  /** The test command as the user runs it (step 6). */
  base: string;
  check: string;
  /** One baseline command per environment label of step 5, or one without a label. */
  baseline: string[];
  scan: string[];
}

/** The default C for the package manager (perf 04-REQ-55). */
export function testCommand(manager: PackageManager): string {
  return manager === 'npm'
    ? 'npx playwright test'
    : manager === 'pnpm'
      ? 'pnpm exec playwright test'
      : 'yarn playwright test';
}

/** A script of package.json that runs Playwright tests. */
const PLAYWRIGHT_TEST = /\bplaywright\s+test\b/u;

/** `npm run <name>` and its forms for the package manager (perf 04-REQ-55). */
export function scriptCommand(manager: PackageManager, name: string): string {
  return manager === 'yarn' ? `yarn ${name}` : `${manager} run ${name}`;
}

/**
 * The default answer of step 6 (perf 04-REQ-55, perf 04-D-50): the only script with `playwright test` in
 * the package manager's form, else the command of the package manager.
 */
export function defaultTestCommand(
  manager: PackageManager,
  scripts: Readonly<Record<string, string>>,
): string {
  const runs = Object.keys(scripts).filter((name) => PLAYWRIGHT_TEST.test(scripts[name] ?? ''));
  return runs.length === 1 ? scriptCommand(manager, runs[0] as string) : testCommand(manager);
}

/** What step 6 says about the script a command runs (perf 04-REQ-55, perf 04-D-50). */
export interface ScriptHints {
  /** The command or its script sets --reporter (RUN_REPORTER_FLAG, perf 04-REQ-61). */
  reporter: boolean;
  /** Commands before `playwright test` in the script, chained with && or ;, else null. */
  everyPass: string | null;
}

/** The package.json script a command runs (`npm run x`, `pnpm x`, `yarn run x`), or null. */
export function scriptOf(
  command: string,
  scripts: Readonly<Record<string, string>>,
): { name: string; text: string } | null {
  const m =
    /^(?:npm\s+(?:run|run-script)|pnpm(?:\s+run)?|yarn(?:\s+run)?)\s+([^\s'"&|;]+)(?:\s|$)/u.exec(
      command.trim(),
    );
  const name = m?.[1];
  if (name === undefined || !Object.hasOwn(scripts, name)) return null;
  return { name, text: scripts[name] as string };
}

/** The hints of step 6 for the command and the script it runs (perf 04-REQ-55, perf 04-D-50). */
export function scriptHints(
  command: string,
  scripts: Readonly<Record<string, string>>,
): ScriptHints {
  const script = scriptOf(command, scripts)?.text ?? '';
  const reporter = /(?:^|\s)--reporter(?:[=\s]|$)/u;
  let everyPass: string | null = null;
  const at = script.search(PLAYWRIGHT_TEST);
  if (at > 0) {
    const before = script.slice(0, at);
    const separators = [...before.matchAll(/&&|;/gu)];
    const last = separators.at(-1);
    if (last !== undefined) everyPass = before.slice(0, last.index).trim() || null;
  }
  return { reporter: reporter.test(command) || reporter.test(script), everyPass };
}

/**
 * The run commands of every mode (11-REQ-13): `PW_SEC_MODE=m C` with C as typed, with
 * `PW_SEC_ENV=<label>` for each environment label of step 5, on Windows with cross-env.
 */
export function runCommands(
  command: string,
  platform: string,
  envs: readonly string[] = [],
): RunCommands {
  const prefix = platform === 'win32' ? 'npx cross-env ' : '';
  const mode = (m: string, env?: string): string =>
    `${prefix}PW_SEC_MODE=${m}${env === undefined ? '' : ` PW_SEC_ENV=${env}`} ${command}`;
  const labels: (string | undefined)[] = envs.length === 0 ? [undefined] : [...envs];
  return {
    base: command,
    check: mode('check'),
    baseline: labels.map((env) => mode('baseline', env)),
    scan: labels.map((env) => mode('scan', env)),
  };
}

/** Internal variable of the wizard's check (11-REQ-10): the directory of the baseline file. */
export const BASELINE_DIR_ENV = 'PW_SEC_BASELINE_DIR';

export interface CheckRun {
  mode: 'check' | 'baseline' | 'scan';
  env: Record<string, string>;
  /** The command as shown, with the mode variable in front. */
  shown: string;
}

/**
 * The three runs of the check (11-REQ-10): check, then baseline and scan with the baseline in
 * `baselineDir`. The variables go to the environment of the child process, not in front of the
 * command, so no cross-env is needed and chains get them too.
 */
export function checkRuns(command: string, platform: string, baselineDir: string): CheckRun[] {
  const prefix = platform === 'win32' ? 'npx cross-env ' : '';
  return (['check', 'baseline', 'scan'] as const).map((mode): CheckRun => ({
    mode,
    env:
      mode === 'check'
        ? { PW_SEC_MODE: mode }
        : { PW_SEC_MODE: mode, [BASELINE_DIR_ENV]: baselineDir },
    shown: `${prefix}PW_SEC_MODE=${mode} ${command}`,
  }));
}

export function commandProblem(command: string): 'variable' | null {
  return /PW_SEC_/u.test(command) ? 'variable' : null;
}

/**
 * True when the command chains commands outside quotes (`&&`, `||`, `;`, `|`): a
 * `PW_PERF_MODE=m ` prefix only reaches the first one (perf 04-REQ-55). A POSIX-like scan of quotes
 * and backslashes; good enough for a hint.
 */
export function chainsCommands(command: string): boolean {
  let quote: '"' | "'" | null = null;
  for (let i = 0; i < command.length; i += 1) {
    const c = command[i];
    if (quote === "'") {
      if (c === "'") quote = null;
    } else if (c === '\\') {
      i += 1;
    } else if (quote === '"') {
      if (c === '"') quote = null;
    } else if (c === '"' || c === "'") {
      quote = c;
    } else if (c === ';' || c === '|' || (c === '&' && command[i + 1] === '&')) {
      return true;
    }
  }
  return false;
}

export interface SpawnSpec {
  file: string;
  args: string[];
  /** false, true (the platform shell) or the path of a shell. */
  shell: boolean | string;
}

/**
 * The process of the wizard's check run (perf 04-REQ-58), without spawning. The default C runs the
 * Playwright CLI of the project through Node, without a shell; an error means: show the command
 * instead. Any other C runs as typed through the user's shell: $SHELL (an absolute path) or
 * /bin/sh on POSIX, %ComSpec% on Windows. PW_PERF_MODE goes in the environment, not here.
 */
export function commandSpawn(input: {
  /** C, the answer of step 6. */
  command: string;
  /** process.execPath. */
  nodePath: string;
  /** The Playwright CLI script, or null when @playwright/test is not installed. */
  playwrightCli: string | null;
  packageManager: PackageManager;
  platform: string;
  /** $SHELL. */
  shell: string | undefined;
}): Result<SpawnSpec, CliIssue> {
  if (input.command !== testCommand(input.packageManager)) {
    const shell =
      input.platform === 'win32'
        ? true
        : input.shell !== undefined && input.shell.startsWith('/')
          ? input.shell
          : '/bin/sh';
    return { ok: true, value: { file: input.command, args: [], shell } };
  }
  if (input.playwrightCli === null) {
    return {
      ok: false,
      issues: [
        {
          code: 'INIT_MANUAL_STEP',
          message: '@playwright/test is not installed here',
          hint: `Run the check command yourself: ${runCommands(input.command, input.platform).check}`,
        },
      ],
    };
  }
  return {
    ok: true,
    value: { file: input.nodePath, args: [input.playwrightCli, 'test'], shell: false },
  };
}
