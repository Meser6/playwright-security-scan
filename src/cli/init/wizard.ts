// The init wizard (11): the tutorial question (0a), the language (0) and nine steps, each with a
// short lesson. Interactive only when stdin and stdout are terminals; without a terminal it takes
// the default answers and only shows the plan, like PW_SEC_DRY_RUN=1 (11-REQ-04). Declining the
// tutorial (or PW_SEC_NO_TUTORIAL=1) prints the manual setup and changes nothing. Texts in the
// chosen language (11-REQ-05), colors by 04-REQ-05. Nothing is written before step 7 (11-REQ-14).
// The dialog and the flow follow the wizard of the perf package (same author).
import { asciiTerminal } from '../../core/report/term/box.ts';
import { colorEnabled, painter } from '../../core/report/term/color.ts';
import type { ColorStyle, Painter } from '../../core/report/term/color.ts';
import {
  BINARY_NAME,
  CONFIG_FILE_BASENAME,
  DOCS_URL,
  INIT_COMMAND,
  PACKAGE_NAME,
  REPORT_DIR,
} from '../constants.ts';
import type { CliIssue } from '../constants.ts';
import type { CliHost, Prompt } from '../host.ts';
import { formatIssues, infoLine } from '../output.ts';
import type { OutputStyle } from '../output.ts';
import { detectProject } from './detect.ts';
import type { ProjectInfo } from './detect.ts';
import { findPlaywrightConfigs, readProjectFiles } from './files.ts';
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

/** Steps shown as [n/9] (11, chapter 4); a skipped step keeps its number. */
const STEPS = 9;
/** Step 0a and step 0 come before the language is known: English (11, chapter 4). */
const TUTORIAL_QUESTION = `Set up ${PACKAGE_NAME} with a guided tutorial?`;
const LANGUAGE_QUESTION = `Language / Język? [${LANGUAGES.join('/')}]`;

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

  /** Step header in cyan ("[1/9] The package") and the lesson dimmed. */
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
  return info.existing.secConfig ?? `${CONFIG_FILE_BASENAME}.${info.typescript ? 'ts' : 'js'}`;
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
    ...table([
      ['PW_SEC_ENV=<label>', t('varEnv')],
      ['PW_SEC_MAX_TESTS=<n>', t('varMaxTests')],
    ]),
    `  ${paint(t('filesTitle'), 'bold')}`,
    ...table([
      [configFile, t('fileConfig')],
      ['security-baseline*.json', t('fileBaseline')],
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
    const { t } = dialog;

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
    // Steps 2 to 9 follow in WP-27 and WP-28; until then the manual setup.
    printManualSetup(dialog);
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
