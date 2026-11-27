// The IMPORTANT box that ends the wizard after a write (11-REQ-13): the way from the written setup
// to a scan in CI that fails only on new findings, with the exact commands of the project. Pure.
// After the perf package.
import { box, marks } from '../../core/report/term/box.ts';
import type { BoxLine } from '../../core/report/term/box.ts';
import type { RunCommands } from './commands.ts';
import type { Translate } from './messages.ts';

/** The box is at most this wide. */
export const IMPORTANT_BOX_MAX_WIDTH = 80;
const MIN_WIDTH = 40;
/** Continuation lines of a numbered point start under its text ("1. "). */
const INDENT = 3;

export interface ImportantBoxInput {
  t: Translate;
  commands: RunCommands;
  /** Baseline files to review and commit. */
  files: readonly string[];
  /** report.dir, relative to the playwright.config directory. */
  reportDir: string;
  /** The red box is shown: the fixture comes first. */
  fixFirst: boolean;
  /** win32: the PowerShell and cmd forms are in docs/cli.md. */
  windows: boolean;
  /** Link of the CI recipes. */
  ciUrl: string;
}

export interface ImportantBoxOptions {
  /** Terminal columns; 0 or undefined: unknown. */
  columns: number | undefined;
  color: boolean;
  /** TERM=dumb: ASCII frame and "!". */
  ascii: boolean;
}

/** Width of the box: the terminal, at most 80 and at least 40; 80 when unknown. */
export function importantBoxWidth(columns: number | undefined): number {
  const known = columns !== undefined && columns > 0 ? columns : IMPORTANT_BOX_MAX_WIDTH;
  return Math.min(IMPORTANT_BOX_MAX_WIDTH, Math.max(MIN_WIDTH, known));
}

/** The IMPORTANT box; every line ends with a newline. */
export function importantBox(input: ImportantBoxInput, opts: ImportantBoxOptions): string {
  const { t, commands, reportDir } = input;
  const point = (n: number, text: string): BoxLine => ({ text: `${n}. ${text}`, indent: INDENT });
  const command = (text: string): BoxLine => ({
    text: `${' '.repeat(INDENT)}${text}`,
    style: 'cyan',
    indent: INDENT,
  });
  const under = (text: string): BoxLine => ({
    text: `${' '.repeat(INDENT)}${text}`,
    indent: INDENT,
  });
  const lines: BoxLine[] = [
    { text: t('importantIntro'), style: 'bold' },
    ...(input.fixFirst ? [{ text: t('importantFixFirst'), style: 'red' } as const] : []),
    { text: '' },
    point(1, t('importantBaseline')),
    command(commands.baseline),
    { text: '' },
    point(
      2,
      t('importantReview', { files: input.files.join(', '), report: `${reportDir}/report.html` }),
    ),
    { text: '' },
    point(3, t('importantCommit', { files: input.files.join(', ') })),
    { text: '' },
    point(4, t('importantScan')),
    command(commands.scan),
    under(t('importantResults', { outcome: `${reportDir}/outcome.json`, url: input.ciUrl })),
    ...(input.windows ? [{ text: '' }, { text: t('windowsNote'), style: 'dim' } as const] : []),
  ];
  return box(lines, {
    width: importantBoxWidth(opts.columns),
    color: opts.color,
    ascii: opts.ascii,
    border: 'yellow',
    title: `${marks(opts.ascii).warn} ${t('importantTitle')}`,
    wrap: true,
  });
}
