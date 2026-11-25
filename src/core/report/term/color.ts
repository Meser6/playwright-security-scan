// Copied from playwright-performance-regression src/console/color.ts (MIT, same author); spec 04-REQ-05.
// The spec IDs in the comments below are those of the perf specification.
// Terminal colors (04-REQ-44): 16 ANSI colors with a fixed meaning, used by the init wizard, the
// package messages, the run summary and the thresholds diff. Colors never carry information alone
// (symbols and words stay), so the text without them is the same apart from the ANSI sequences.
// Pure: the caller passes the stream and the environment.

/** green: success/passed, red: error/blocking, yellow: warning, magenta: tool error (result not
 * trustworthy), cyan: step headers and command names, dim: explanations, hints and default
 * values, bold: headings and emphasis (questions, file names). The badges are bold text on a
 * background of the verdict color (09-REQ-29). */
export type ColorStyle =
  | 'green'
  | 'red'
  | 'yellow'
  | 'magenta'
  | 'cyan'
  | 'dim'
  | 'bold'
  | 'badge-green'
  | 'badge-yellow'
  | 'badge-red'
  | 'badge-magenta';

const ANSI: Record<ColorStyle, string> = {
  green: '\u001b[32m',
  red: '\u001b[31m',
  yellow: '\u001b[33m',
  magenta: '\u001b[35m',
  cyan: '\u001b[36m',
  dim: '\u001b[2m',
  bold: '\u001b[1m',
  // Black on the light backgrounds, bright white on the dark ones.
  'badge-green': '\u001b[1;30;42m',
  'badge-yellow': '\u001b[1;30;43m',
  'badge-red': '\u001b[1;97;41m',
  'badge-magenta': '\u001b[1;97;45m',
};
const RESET = '\u001b[0m';

/**
 * Whether output on `stream` gets colors: never with a non-empty NO_COLOR; with FORCE_COLOR other
 * than "0" also without a terminal; FORCE_COLOR=0 turns them off; otherwise only in a terminal
 * whose TERM is not "dumb".
 */
export function colorEnabled(
  stream: { isTTY?: boolean | undefined },
  env: Readonly<Record<string, string | undefined>>,
): boolean {
  if ((env.NO_COLOR ?? '') !== '') return false;
  const force = env.FORCE_COLOR;
  if (force !== undefined) return force !== '0';
  return stream.isTTY === true && env.TERM !== 'dumb';
}

/** `text` in `style` when `enabled`, otherwise unchanged. */
export function paint(text: string, style: ColorStyle, enabled: boolean): string {
  return enabled && text !== '' ? `${ANSI[style]}${text}${RESET}` : text;
}

/** A painter bound to one color decision. */
export type Painter = (text: string, style: ColorStyle) => string;

export function painter(enabled: boolean): Painter {
  return (text, style) => paint(text, style, enabled);
}

// eslint-disable-next-line no-control-regex
const SEQUENCE = /\u001b\[[0-9;]*m/gu;

/** Removes the SGR sequences written by paint. */
export function stripAnsi(text: string): string {
  return text.replace(SEQUENCE, '');
}
