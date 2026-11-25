// Messages of the binary and the wizard (11): on stderr, in English, each line prefixed with the
// package name; errors and warnings with their code and a hint. Colors by the rules of
// perf 04-REQ-05 (colorEnabled). Pure.
import { colorEnabled, paint as paintText } from '../core/report/term/color.ts';
import { PACKAGE_NAME } from './constants.ts';
import type { Issue } from './constants.ts';

export const PREFIX = `${PACKAGE_NAME}: `;

export interface OutputStyle {
  color: boolean;
}

/** The output style of `stream` (perf 04-REQ-05). */
export function outputStyle(
  stream: { isTTY?: boolean | undefined },
  env: Readonly<Record<string, string | undefined>>,
): OutputStyle {
  return { color: colorEnabled(stream, env) };
}

function paint(text: string, style: 'red' | 'yellow' | 'green', opts: OutputStyle): string {
  return paintText(text, style, opts.color);
}

/** One informational line. */
export function infoLine(text: string): string {
  return `${PREFIX}${text}\n`;
}

/** An error or warning: code, message, then the hint lines indented. */
export function formatIssue(issue: Issue, level: 'error' | 'warning', opts: OutputStyle): string {
  const label = paint(`${level} ${issue.code}`, level === 'error' ? 'red' : 'yellow', opts);
  const lines = [`${PREFIX}${label}: ${issue.message}`];
  if (issue.hint !== undefined) {
    for (const line of issue.hint.split('\n')) lines.push(`  ${line}`);
  }
  return `${lines.join('\n')}\n`;
}

export function formatIssues(
  issues: readonly Issue[],
  level: 'error' | 'warning',
  opts: OutputStyle,
): string {
  return issues.map((issue) => formatIssue(issue, level, opts)).join('');
}
