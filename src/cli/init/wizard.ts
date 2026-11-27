// The init wizard (11): the tutorial question (0a), the language (0) and eight steps shown as
// [n/8] (step IDs of 11, chapter 4, without step 5, D-17), each with a short lesson. Interactive only when stdin and stdout are terminals; without a terminal it takes
// the default answers and only shows the plan, like PW_SEC_DRY_RUN=1 (11-REQ-04). Declining the
// tutorial (or PW_SEC_NO_TUTORIAL=1) prints the manual setup and changes nothing. Texts in the
// chosen language (11-REQ-05), colors by 04-REQ-05. Nothing is written before step 7 (11-REQ-14).
// The dialog and the flow follow the wizard of the perf package (same author).
import { asciiTerminal, box as renderBox } from '../../core/report/term/box.ts';
import type { BoxLine } from '../../core/report/term/box.ts';
import { SEVERITIES } from '../../core/types/index.ts';
import type { Severity } from '../../core/types/index.ts';
import type { Preset } from '../../core/config/index.ts';
import { colorEnabled, painter } from '../../core/report/term/color.ts';
import type { ColorStyle, Painter } from '../../core/report/term/color.ts';
import { BINARY_NAME, DOCS_URL, INIT_COMMAND, PACKAGE_NAME, REPORT_DIR } from '../constants.ts';
import type { CliIssue } from '../constants.ts';
import type { CliHost, Prompt } from '../host.ts';
import { formatIssues, infoLine } from '../output.ts';
import type { OutputStyle } from '../output.ts';
import {
  chainsCommands,
  checkRun,
  commandProblem,
  commandSpawn,
  defaultTestCommand,
  runCommands,
  scriptHints,
} from './commands.ts';
import type { RunCommands } from './commands.ts';
import { readCheckOutput } from './check-output.ts';
import type { CheckOutput } from './check-output.ts';
import { importantBox } from './next-steps.ts';
import { detectProject, originOf } from './detect.ts';
import type { ProjectInfo } from './detect.ts';
import { unifiedDiff } from './diff.ts';
import { findPlaywrightConfigs, readProjectFiles } from './files.ts';
import { isProtected, planInitChanges, secConfigFile } from './plan.ts';
import type { FileChange, TestObjectBox } from './plan.ts';
import type { InitAnswers } from './sec-config.ts';
import { LANGUAGES, LANGUAGE_NAMES, isWizardLanguage, translator } from './messages.ts';
import type { MessageKey, MessageValues, Translate, WizardLanguage } from './messages.ts';
import { PromptAborted } from './prompt.ts';

/** The wizard settings from PW_SEC_DRY_RUN, PW_SEC_LANG and PW_SEC_NO_TUTORIAL (11-REQ-03). */
export interface InitCommand {
  dryRun: boolean;
  lang?: WizardLanguage;
  noTutorial?: boolean;
}

/** "1.57.0" ≥ "1.57.0"; pre-release parts are ignored. */
export function versionAtLeast(version: string, minimum: string): boolean {
  const parts = (v: string): number[] =>
    v
      .split(/[.+-]/u)
      .slice(0, 3)
      .map((p) => Number.parseInt(p, 10) || 0);
  const a = parts(version);
  const b = parts(minimum);
  for (let i = 0; i < 3; i += 1) {
    if ((a[i] ?? 0) !== (b[i] ?? 0)) return (a[i] ?? 0) > (b[i] ?? 0);
  }
  return true;
}

/** Steps shown as [n/8] (11, chapter 4; no environment step, D-17); a skipped step keeps its number. */
const STEPS = 8;
/** Step 0a and step 0 come before the language is known: English (11, chapter 4). */
const TUTORIAL_QUESTION = `Set up ${PACKAGE_NAME} with a guided tutorial?`;
const LANGUAGE_QUESTION = `Language / Język? [${LANGUAGES.join('/')}]`;
/** Warning code of the red box (11-REQ-08). */
const TEST_OBJECT_CODE = 'INIT_TEST_OBJECT_MANUAL';
const PRESETS: readonly Preset[] = ['recommended', 'strict', 'minimal'];

class WriteFailed extends Error {}

/** Asks questions in a terminal, or prints the default answer without one. */
class Dialog {
  readonly #host: CliHost;
  readonly #prompt: Prompt | null;
  readonly #style: OutputStyle;
  /** Colors of stdout (04-REQ-05). */
  readonly paint: Painter;
  readonly colors: boolean;
  /** TERM=dumb: ASCII frames. */
  readonly ascii: boolean;
  t: Translate = translator('en');

  constructor(host: CliHost, prompt: Prompt | null, style: OutputStyle) {
    this.#host = host;
    this.#prompt = prompt;
    this.#style = style;
    this.colors = colorEnabled(host.stdout, host.env);
    this.paint = painter(this.colors);
    this.ascii = asciiTerminal(host.env);
  }

  get interactive(): boolean {
    return this.#prompt !== null;
  }

  say(...lines: string[]): void {
    this.#host.stdout.write(lines.map((l) => `${l}\n`).join(''));
  }

  /** An indented line in one color. */
  line(text: string, style: ColorStyle, indent = '  '): void {
    this.say(`${indent}${this.paint(text, style)}`);
  }

  /** Step header in cyan ("[1/8] The package") and the lesson dimmed. */
  step(n: number | string, title: string, ...lesson: string[]): void {
    this.say('', this.paint(`[${n}/${STEPS}] ${title}`, 'cyan'));
    for (const l of lesson) this.line(l, 'dim');
  }

  stepOf(n: number, title: MessageKey, ...lesson: MessageKey[]): void {
    this.step(n, this.t(title), ...lesson.map((k) => this.t(k)));
  }

  warn(issues: readonly CliIssue[]): void {
    if (issues.length > 0) this.#host.stderr.write(formatIssues(issues, 'warning', this.#style));
  }

  error(
    code: string,
    message: MessageKey,
    hint: MessageKey | string[],
    values: MessageValues,
  ): number {
    const hintText = typeof hint === 'string' ? this.t(hint, values) : hint.join('\n');
    this.#host.stderr.write(
      formatIssues(
        [{ code, message: this.t(message, values), hint: hintText }],
        'error',
        this.#style,
      ),
    );
    return 3;
  }

  /**
   * A question with a default; `parse` returns the value or null to ask again, with `again(answer)`
   * as the reason when given.
   */
  async ask<T>(
    question: string,
    shownDefault: string,
    fallback: T,
    parse: (answer: string) => T | null,
    fallbackText = shownDefault,
    again?: (answer: string) => string,
  ): Promise<T> {
    const text = `  ${this.paint(question, 'bold')} ${this.paint(`(${shownDefault})`, 'dim')} `;
    if (this.#prompt === null) {
      this.say(`${text}→ ${this.paint(fallbackText, 'bold')}`);
      return fallback;
    }
    for (;;) {
      const answer = (await this.#prompt.ask(text)).trim();
      if (answer === '') return fallback;
      const value = parse(answer);
      if (value !== null) return value;
      this.line(`⚠ ${again === undefined ? this.t('answerAgain') : again(answer)}`, 'yellow');
    }
  }

  confirm(question: string, fallback: boolean): Promise<boolean> {
    const t = this.t;
    const y = t('yesShort');
    const n = t('noShort');
    const yes = new Set(['y', 'yes', y, t('yes')]);
    const no = new Set(['n', 'no', n, t('no')]);
    return this.ask(
      question,
      fallback ? `${y.toUpperCase()}/${n}` : `${y}/${n.toUpperCase()}`,
      fallback,
      (a) => {
        const answer = a.toLowerCase();
        return yes.has(answer) ? true : no.has(answer) ? false : null;
      },
      fallback ? t('yes') : t('no'),
    );
  }

  async pause(): Promise<void> {
    if (this.#prompt !== null)
      await this.#prompt.ask(`  ${this.paint(this.t('pressEnter'), 'dim')} `);
  }
}

/** The package config file of the project: the existing one, else pw-sec.config.ts. */
function configFileName(info: ProjectInfo): string {
  return info.existing.secConfig ?? secConfigFile(info).path;
}

/** Step 1 after the lesson: how to use the package, the other variables and the files. */
function printUsage(dialog: Dialog, platform: string, configFile: string): void {
  const { t, paint } = dialog;
  const prefix = platform === 'win32' ? 'npx cross-env ' : '';
  const command = t('usageCommandPlaceholder');
  const mode = (m: string): string => paint(`${prefix}PW_SEC_MODE=${m} ${command}`, 'cyan');
  const table = (rows: readonly (readonly [string, string])[]): string[] => {
    const width = Math.max(...rows.map(([name]) => name.length));
    return rows.map(([name, text]) => `    ${paint(name.padEnd(width), 'cyan')}  ${text}`);
  };
  dialog.say(
    `  ${paint(t('usageTitle'), 'bold')}`,
    `    1. ${mode('check')}`,
    `       ${t('usageCheck')}`,
    `    2. ${mode('baseline')}`,
    `       ${t('usageBaseline')}`,
    `    3. ${t('usageReview')}`,
    `    4. ${mode('scan')}`,
    `       ${t('usageScan')}`,
  );
  dialog.line(t('usageCommand'), 'dim');
  dialog.say(
    `  ${paint(t('variablesTitle'), 'bold')}`,
    ...table([['PW_SEC_MAX_TESTS=<n>', t('varMaxTests')]]),
    `  ${paint(t('filesTitle'), 'bold')}`,
    ...table([
      [configFile, t('fileConfig')],
      [BASELINE_FILE, t('fileBaseline')],
      [`${REPORT_DIR}/`, t('fileReport')],
    ]),
  );
}

/** Step 0a declined or PW_SEC_NO_TUTORIAL=1: the manual setup, no changes. */
function printManualSetup(dialog: Dialog): void {
  const { t, paint } = dialog;
  const cmd = (text: string): string => paint(text, 'cyan');
  dialog.say('');
  dialog.line(`✔ ${t('declinedInstalled', { pkg: PACKAGE_NAME })}`, 'green');
  dialog.say(
    `  ${paint(t('declinedSteps'), 'bold')}`,
    `    1. ${t('declinedConfig', { config: `${PACKAGE_NAME}/config` })}`,
    `    2. ${t('declinedTest', { fixture: `${PACKAGE_NAME}/fixture`, test: `${PACKAGE_NAME}/test` })}`,
    `    3. ${t('declinedRun', { example: cmd('PW_SEC_MODE=baseline npx playwright test') })}`,
  );
  dialog.line(t('declinedDocs', { url: `${DOCS_URL}/adoption.md` }), 'dim');
  dialog.say(`  ${t('declinedLater', { init: cmd(INIT_COMMAND) })}`);
}

/** Step 0: the language from PW_SEC_LANG, the answer in a terminal, or English (11-REQ-05). */
async function askLanguage(
  dialog: Dialog,
  given: WizardLanguage | undefined,
): Promise<WizardLanguage> {
  dialog.step(0, 'Language');
  dialog.line(LANGUAGES.map((l) => `${l} ${LANGUAGE_NAMES[l]}`).join(' · '), 'dim');
  if (given !== undefined) {
    dialog.say(
      `  ${dialog.paint(LANGUAGE_QUESTION, 'bold')} ${dialog.paint('(en)', 'dim')} → ${dialog.paint(given, 'bold')}`,
    );
    return given;
  }
  return dialog.ask<WizardLanguage>(LANGUAGE_QUESTION, 'en', 'en', (a) => {
    const code = a.toLowerCase();
    if (isWizardLanguage(code)) return code;
    return LANGUAGES.find((l) => LANGUAGE_NAMES[l].toLowerCase() === code) ?? null;
  });
}

/** A comma-separated list; null when an item fails `valid`, with the bad item in `bad`. */
function listAnswer(
  answer: string,
  valid: (item: string) => string | null,
  bad: { value: string },
): string[] | null {
  const items: string[] = [];
  for (const raw of answer
    .split(',')
    .map((x) => x.trim())
    .filter((x) => x !== '')) {
    const item = valid(raw);
    if (item === null) {
      bad.value = raw;
      return null;
    }
    if (!items.includes(item)) items.push(item);
  }
  return items;
}

/** Steps 2 to 6 (11, chapter 4). */
async function askAnswers(dialog: Dialog, info: ProjectInfo): Promise<InitAnswers> {
  const { t, paint } = dialog;
  dialog.stepOf(
    2,
    'stepRules',
    'rulesLesson',
    'presetRecommended',
    'presetStrict',
    'presetMinimal',
  );
  const preset = await dialog.ask<Preset>(
    t('presetQuestion'),
    'recommended',
    'recommended',
    (a) => {
      const answer = a.toLowerCase() as Preset;
      return PRESETS.includes(answer) ? answer : null;
    },
  );

  dialog.stepOf(3, 'stepGate', 'gateLesson');
  const levels: readonly Severity[] = SEVERITIES.filter((s) => s !== 'info');
  const minSeverity = await dialog.ask<Severity>(t('gateQuestion'), 'medium', 'medium', (a) => {
    const answer = a.toLowerCase() as Severity;
    return answer !== 'info' && levels.includes(answer) ? answer : null;
  });

  dialog.stepOf(4, 'stepOrigins', 'originsLesson');
  if (info.baseOrigin !== null) dialog.line(t('originsBase', { origin: info.baseOrigin }), 'dim');
  else dialog.line(t('originsNoBase'), 'dim');
  if (info.foundOrigins.length > 0) {
    dialog.line(t('originsFound'), 'dim');
    for (const origin of info.foundOrigins) dialog.say(`    ${paint(origin, 'cyan')}`);
  }
  const badOrigin = { value: '' };
  const origins = await dialog.ask<string[]>(
    t('originsQuestion'),
    '-',
    [],
    (a) =>
      listAnswer(a, (x) => (/^https?:\/\/[^/\s]+\/?$/u.test(x) ? originOf(x) : null), badOrigin),
    '-',
    () => t('originsInvalid', { value: badOrigin.value }),
  );

  // Step 6: the test command C as typed; Enter keeps the default, 'skip' also skips the check.
  dialog.stepOf(5, 'stepCommand', 'commandLesson1', 'commandLesson2');
  const suggested = defaultTestCommand(info.packageManager, info.scriptTexts);
  // An answer is never empty (Enter gives the default), so '' stands for 'skip'.
  const typed = await dialog.ask<string>(
    t('commandQuestion'),
    suggested,
    suggested,
    (a) => (a.toLowerCase() === 'skip' ? '' : commandProblem(a) === null ? a : null),
    suggested,
    () => t('commandVariable'),
  );
  const skipped = typed === '';
  const command = skipped ? suggested : typed;
  if (chainsCommands(command)) dialog.line(`⚠ ${t('commandChain')}`, 'yellow');
  if (scriptHints(command, info.scriptTexts).reporter)
    dialog.line(`⚠ ${t('commandReporter')}`, 'yellow');

  return { preset, minSeverity, origins, command, runCheck: dialog.interactive && !skipped };
}

/** Words of `text` in lines of at most `width` characters. */
function wrapText(text: string, width: number): string[] {
  const lines: string[] = [];
  let line = '';
  for (const word of text.split(' ')) {
    if (line !== '' && line.length + 1 + word.length > width) {
      lines.push(line);
      line = word;
    } else line = line === '' ? word : `${line} ${word}`;
  }
  if (line !== '') lines.push(line);
  return lines;
}

/**
 * Variant (a) of the red box (11-REQ-08): the files with `.extend(`, the most imported by
 * test files first, the one to wrap when one is imported more than the others, and where to
 * install the package for a fixtures module in a workspace package.
 */
function fixtureLines(box: TestObjectBox, t: Translate, inner: number): BoxLine[] {
  if (box.extendFiles.length === 0) return [];
  const dim = (s: string): BoxLine[] => wrapText(s, inner).map((l) => ({ text: l, style: 'dim' }));
  const count = (file: string): number => box.importedBy[file] ?? 0;
  const lines: BoxLine[] = [
    ...dim(t('boxFixturesFiles')),
    ...box.extendFiles.flatMap((file) => dim(`  ${file} · ${count(file)}`)),
  ];
  const [first, second] = box.extendFiles;
  if (
    first !== undefined &&
    count(first) > 0 &&
    (second === undefined || count(first) > count(second))
  )
    lines.push(...wrapText(t('boxWrapThis', { file: first }), inner).map((l) => ({ text: l })));
  for (const file of box.extendFiles) {
    const pkg = box.workspace[file];
    if (pkg !== undefined) lines.push(...dim(t('boxWorkspace', { file, pkg, self: PACKAGE_NAME })));
  }
  return lines;
}

/** The red box (11-REQ-08): what to paste so that the tests are scanned. */
function testObjectBox(dialog: Dialog, host: CliHost, box: TestObjectBox): string {
  const { t } = dialog;
  const columns = host.stdout.columns ?? 0;
  const width = Math.min(100, Math.max(40, columns > 0 ? columns : 100));
  const inner = width - 4;
  const text = (s: string, style?: ColorStyle): BoxLine[] =>
    wrapText(s, inner).map((l) => (style === undefined ? { text: l } : { text: l, style }));
  const lines: BoxLine[] = [
    { text: `${dialog.ascii ? '!' : '✖'} ${TEST_OBJECT_CODE} · ${t('boxTitle')}`, style: 'bold' },
    { text: '' },
    ...text(t('boxWhy')),
    { text: '' },
    ...text(`(a) ${t('boxFixtures')}`, 'bold'),
    ...fixtureLines(box, t, inner),
    { text: `    import { withSecurityFixtures } from '${PACKAGE_NAME}/fixture';`, style: 'cyan' },
    { text: '    export const test = withSecurityFixtures(base.extend({ ... }));', style: 'cyan' },
    { text: '' },
    ...text(`(b) ${t('boxImports', { count: box.importingFiles })}`, 'bold'),
    { text: `    import { test, expect } from '${PACKAGE_NAME}/test';`, style: 'cyan' },
    { text: '' },
    ...text(t('boxDocs', { url: `${DOCS_URL}/adoption.md` }), 'dim'),
  ];
  return renderBox(lines, { width, color: dialog.colors, ascii: dialog.ascii, border: 'red' });
}

function changeKind(change: FileChange, t: Translate): string {
  return change.kind === 'create' ? t('newFile') : t('modifiedFile');
}

/** Diff lines: added green, removed red, hunk headers cyan, file headers bold (11-REQ-06). */
function diffStyle(line: string): ColorStyle | null {
  if (line.startsWith('+++') || line.startsWith('---')) return 'bold';
  if (line.startsWith('+')) return 'green';
  if (line.startsWith('-')) return 'red';
  if (line.startsWith('@@')) return 'cyan';
  return null;
}

/** The changes step: diffs, confirmations and writes. Returns the paths written. */
async function applyChanges(
  dialog: Dialog,
  host: CliHost,
  info: ProjectInfo,
  changes: readonly FileChange[],
  write: boolean,
  accepted: string[] = [],
): Promise<string[]> {
  const { t, paint } = dialog;
  const written: string[] = [];
  for (const change of changes) {
    dialog.say(
      '',
      `  ${paint(change.path, 'bold')} ${paint(`(${changeKind(change, t)})`, 'dim')}`,
      ...unifiedDiff(change)
        .trimEnd()
        .split('\n')
        .map((l) => {
          const style = diffStyle(l);
          return `    ${style === null ? l : paint(l, style)}`;
        }),
    );
    let apply: boolean;
    if (isProtected(info, change.path)) {
      // Never overwritten without its own confirmation (11-REQ-09).
      if (dialog.interactive)
        apply = await dialog.confirm(t('overwriteQuestion', { path: change.path }), false);
      else {
        dialog.say(`  ${t('kept', { path: change.path })}`);
        apply = false;
      }
    } else {
      apply = await dialog.confirm(t('applyQuestion'), true);
    }
    if (apply) accepted.push(change.path);
    if (!apply || !write) continue;
    try {
      await host.writeText(host.paths.join(host.cwd, change.path), change.after);
    } catch (error) {
      throw new WriteFailed(
        `${change.path}: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    dialog.line(`✔ ${t('fileWritten', { path: change.path })}`, 'green');
    written.push(change.path);
  }
  return written;
}

/** Exit code of the wizard's check, with the cause it translates (11-REQ-11). */
interface CheckResult {
  code: number;
  /** The scan sees the app's traffic (verdict READY or READY WITH WARNINGS). */
  ready: boolean;
  cause: string | null;
}

/** Output of the check kept for its result (11-REQ-11); the check output is short. */
const MAX_CHECK_OUTPUT = 1_000_000;

/**
 * The cause of a check that is not ready, from its output (11-REQ-11): the first error, or no
 * traffic in scope with the origins outside the scope.
 */
function checkCause(dialog: Dialog, output: CheckOutput | null, configFile: string): string | null {
  if (output === null || output.verdict !== 'not-ready') return null;
  if (output.firstError !== null) return `${output.firstError.code}: ${output.firstError.message}`;
  if (!output.noTraffic) return null;
  const cause = dialog.t('checkNoTraffic', { configFile });
  return output.outOfScope.length === 0
    ? cause
    : `${cause} ${dialog.t('checkOutOfScope', { origins: output.outOfScope.join(', ') })}`;
}

/**
 * Step 8 (11-REQ-10): the test command once as a child process with PW_SEC_MODE=check. Its output
 * goes to the terminal and is read for the result (the check writes no file); Ctrl+C (130) stops it.
 */
async function runCheck(
  dialog: Dialog,
  host: CliHost,
  info: ProjectInfo,
  commands: RunCommands,
): Promise<CheckResult | null> {
  const spec = commandSpawn({
    command: commands.base,
    nodePath: host.execPath,
    playwrightCli: host.resolvePlaywright(host.cwd)?.cliPath ?? null,
    packageManager: info.packageManager,
    platform: host.platform,
    shell: host.env.SHELL,
  });
  if (!spec.ok) {
    dialog.line(dialog.t('checkManual', { command: commands.check }), 'yellow');
    return null;
  }
  const inherited: Record<string, string> = {};
  for (const [name, value] of Object.entries(host.env))
    if (value !== undefined && !name.startsWith('PW_SEC_')) inherited[name] = value;
  // The output goes through a pipe: colors stay when the wizard has them.
  if (dialog.colors && host.env.FORCE_COLOR === undefined) inherited.FORCE_COLOR = '1';
  const run = checkRun(commands.base, host.platform);
  // Ctrl+C goes to the whole process group: the run stops and the wizard reports 130.
  const stop = host.onSignal('SIGINT', () => undefined);
  let text = '';
  try {
    dialog.line(`$ ${run.shown}`, 'dim');
    const child = host.spawnProcess(spec.value.file, spec.value.args, {
      cwd: host.cwd,
      env: { ...inherited, ...run.env },
      stdio: ['inherit', 'pipe', 'pipe'],
      shell: spec.value.shell,
    });
    child.stdout?.on('data', (chunk) => {
      const part = String(chunk);
      host.stdout.write(part);
      text = (text + part).slice(-MAX_CHECK_OUTPUT);
    });
    child.stderr?.on('data', (chunk) => host.stderr.write(String(chunk)));
    const code = await new Promise<number>((resolve) => {
      child.once('close', (exit, signal) => resolve(signal === 'SIGINT' ? 130 : (exit ?? 1)));
      child.once('error', () => resolve(1));
    });
    if (code === 130) return { code, ready: false, cause: null };
    const output = readCheckOutput(text);
    const ready = output !== null && output.verdict !== 'not-ready';
    const cause = checkCause(dialog, output, configFileName(info));
    dialog.line(dialog.t('checkExit', { mode: 'check', code }), code === 0 ? 'green' : 'yellow');
    if (cause !== null) dialog.line(dialog.t('checkCause', { cause }), 'yellow');
    return { code, ready, cause };
  } finally {
    stop();
  }
}

/** The baseline file the wizard leaves at its default (baseline.path). */
const BASELINE_FILE = 'security-baseline.json';

export async function runInit(
  cmd: InitCommand,
  host: CliHost,
  style: OutputStyle,
): Promise<number> {
  const interactive = !cmd.dryRun && host.stdin.isTTY === true && host.stdout.isTTY === true;
  const write = interactive;
  const prompt = interactive && cmd.noTutorial !== true ? host.createPrompt() : null;
  const dialog = new Dialog(host, prompt, style);
  try {
    // Step 0a: without a terminal the question is skipped.
    if (cmd.noTutorial === true) {
      dialog.t = translator(cmd.lang ?? 'en');
      printManualSetup(dialog);
      return 0;
    }
    if (interactive && !(await dialog.confirm(TUTORIAL_QUESTION, true))) {
      dialog.t = translator(cmd.lang ?? 'en');
      printManualSetup(dialog);
      return 0;
    }
    const lang = await askLanguage(dialog, cmd.lang);
    dialog.t = translator(lang);
    const { t, paint } = dialog;

    if (!write) host.stderr.write(infoLine(t(cmd.dryRun ? 'dryRun' : 'noTerminal')));
    const info = detectProject(await readProjectFiles(host, host.cwd));
    if (info.playwrightConfig === null) {
      // Right after the language and without writing anything: the configs in subdirectories,
      // each with the command to run there (11, chapter 4, step 1).
      const found = await findPlaywrightConfigs(host, host.cwd);
      const values = { dir: host.cwd, command: INIT_COMMAND };
      return dialog.error(
        'INIT_NO_PLAYWRIGHT_CONFIG',
        'noConfigMessage',
        found.length === 0
          ? 'noConfigHint'
          : [
              t('noConfigFound'),
              ...found.map((path) => {
                const dir = path.split('/').slice(0, -1).join('/');
                return `  cd ${dir} && npx ${BINARY_NAME}   (${path})`;
              }),
            ],
        values,
      );
    }
    // Step 1: what the package does and how to use it; the analysis stays silent and only a too
    // old Playwright stops here.
    dialog.step(1, t('stepProject'), t('about1', { pkg: PACKAGE_NAME }), t('about2'), t('about3'));
    printUsage(dialog, host.platform, configFileName(info));
    if (
      info.playwrightVersion !== null &&
      !versionAtLeast(info.playwrightVersion, host.minPlaywrightVersion)
    ) {
      return dialog.error('INIT_PLAYWRIGHT_TOO_OLD', 'tooOldMessage', 'tooOldHint', {
        version: info.playwrightVersion,
        min: host.minPlaywrightVersion,
        pkg: PACKAGE_NAME,
        command: INIT_COMMAND,
      });
    }
    await dialog.pause();

    const answers = await askAnswers(dialog, info);
    const plan = planInitChanges(info, answers, lang);
    const commands = runCommands(answers.command, host.platform);

    dialog.stepOf(
      6,
      'stepChanges',
      plan.changes.length === 0 ? 'nothingToChange' : 'changesLesson',
    );
    if (
      info.existing.wrappedConfig &&
      plan.changes.some((c) => c.path === info.playwrightConfig?.path)
    )
      dialog.line(`⚠ ${t('perfOrder')}`, 'yellow');
    let written: string[];
    const accepted: string[] = [];
    try {
      written = await applyChanges(dialog, host, info, plan.changes, write, accepted);
    } catch (error) {
      if (!(error instanceof WriteFailed)) throw error;
      return dialog.error('INIT_WRITE_FAILED', 'writeFailedMessage', 'writeFailedHint', {
        detail: error.message,
      });
    }
    dialog.warn(plan.manualSteps);
    // The import changes replace the red box only when every one is applied.
    const testObject =
      plan.testObject ??
      (plan.importSwap !== null && !plan.importSwap.paths.every((p) => accepted.includes(p))
        ? plan.importSwap.box
        : null);
    const redBox = testObject === null ? null : testObjectBox(dialog, host, testObject);
    if (redBox !== null) host.stdout.write(`\n${redBox}`);

    // Step 8: only when something was written (or the project is set up), playwright.config has
    // withSecurity() and step 6 was not skipped (11, chapter 4).
    const configPath = info.playwrightConfig.path;
    const wrapped = info.existing.wrappedConfig || written.includes(configPath);
    const setUp = written.length > 0 || plan.changes.length === 0;
    let checkResult: CheckResult | null = null;
    dialog.stepOf(7, 'stepCheck', 'checkLesson');
    if (answers.runCheck && write && setUp && wrapped && testObject === null) {
      if (await dialog.confirm(t('checkQuestion'), true)) {
        prompt?.close();
        checkResult = await runCheck(dialog, host, info, commands);
        if (checkResult?.code === 130) {
          host.stderr.write(infoLine(t('interrupted')));
          return 130;
        }
        if (checkResult?.ready === true) dialog.line(`✔ ${t('checkPassed')}`, 'green');
      }
    } else {
      dialog.line(t('skipped'), 'dim');
    }

    dialog.step(8, t('stepSummary'));
    if (written.length > 0) {
      dialog.say(
        `  ${t('changedFiles')}`,
        ...written.map((p) => `    ${paint('✔', 'green')} ${p}`),
      );
      dialog.line(t('formatNote'), 'dim');
    } else if (write) dialog.say(`  ${t('noFilesChanged')}`);
    else
      dialog.say(
        `  ${t('plannedChanges')}`,
        ...plan.changes.map((c) => `    · ${c.path} (${changeKind(c, t)})`),
      );
    if (plan.manualSteps.length > 0)
      dialog.line(`⚠ ${t('manualSteps', { count: plan.manualSteps.length })}`, 'yellow');
    if (redBox !== null) host.stdout.write(redBox);
    if (checkResult !== null && checkResult.code !== 0)
      dialog.say(`  ${t('checkExit', { mode: 'check', code: checkResult.code })}`);
    if (checkResult?.cause != null)
      dialog.say(`  ${t('checkCause', { cause: checkResult.cause })}`);
    // After a write the IMPORTANT box has the commands; without one the Run line (11-REQ-13).
    const done = write && setUp;
    if (!done) {
      dialog.say('', `  ${paint(t('runLine', { command: commands.check }), 'bold')}`);
      dialog.line(t('runLesson'), 'dim');
      if (host.platform === 'win32') dialog.line(t('windowsNote'), 'dim');
      dialog.say(`  ${paint(t('nextSteps'), 'bold')}`, `    1. ${t('nextApply')}`);
    } else if (checkResult === null) {
      dialog.say('', `  ${t('tryCheck', { command: paint(commands.check, 'cyan') })}`);
    }
    if (commands.base.includes('&&') || commands.base.includes(';'))
      dialog.line(`⚠ ${t('commandChain')}`, 'yellow');
    const links = [`${DOCS_URL}/adoption.md`, `${DOCS_URL}/cli.md`, `${DOCS_URL}/ci.md`];
    dialog.line(t('docs', { links: links.join(' · ') }), 'dim');
    if (write) dialog.line(`✔ ${t('finished')}`, 'green');
    if (done) {
      const important = importantBox(
        {
          t,
          commands,
          files: [BASELINE_FILE],
          reportDir: REPORT_DIR,
          fixFirst: redBox !== null,
          windows: host.platform === 'win32',
          ciUrl: `${DOCS_URL}/ci.md`,
        },
        { columns: host.stdout.columns, color: dialog.colors, ascii: dialog.ascii },
      );
      host.stdout.write(`\n${important}`);
    }
    return 0;
  } catch (error) {
    if (error instanceof PromptAborted) {
      host.stderr.write(infoLine(dialog.t('interrupted')));
      return 130;
    }
    throw error;
  } finally {
    prompt?.close();
  }
}
