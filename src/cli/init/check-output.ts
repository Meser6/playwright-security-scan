// The result of the wizard's check read from its output (11-REQ-11): the check writes no file
// (04-REQ-11), so the verdict, the diagnostic codes and the origins outside the scope come from
// the lines printed by the reporter (04-REQ-12). Pure.

export type CheckVerdict = 'ready' | 'warnings' | 'not-ready';

export interface CheckOutput {
  verdict: CheckVerdict;
  /** No response was in scope (NO_TRAFFIC or SCOPE_EMPTY). */
  noTraffic: boolean;
  /** The first error of the error box, or null. */
  firstError: { code: string; message: string } | null;
  /** Origins of the table of traffic outside the scope, in its order. */
  outOfScope: string[];
}

// eslint-disable-next-line no-control-regex -- ANSI color sequences of the reporter
const ANSI = /\u001b\[[0-9;]*m/gu;
const HEADER = /playwright-security-scan · check · /u;
const DIAGNOSTIC = /^\S+\s+([A-Z][A-Z0-9_]+): (.*)$/u;
/** The verdict box: a mark, then the verdict word (04-REQ-12, item 6). */
const VERDICT = /^\S+\s+(NOT READY|READY WITH WARNINGS|READY)(?:\s|$)/u;
const ORIGIN = /https?:\/\/[^\s│|]+/u;

/** A line without colors and without the borders of a box or a table. */
function plain(line: string): string {
  return line
    .replace(ANSI, '')
    .replace(/^[\s│|├└┌╭╰+]+/u, '')
    .replace(/[\s│|┤┘┐╮╯+]+$/u, '');
}

/**
 * Reads the output of the last check in `text` (stdout of the test command), or returns null when
 * there is none (for example the reporter of the package is not in the config).
 */
export function readCheckOutput(text: string): CheckOutput | null {
  const lines = text.split(/\r?\n/u).map(plain);
  let start = -1;
  lines.forEach((line, i) => {
    if (HEADER.test(line)) start = i;
  });
  if (start < 0) return null;
  let verdict: CheckVerdict | null = null;
  let noTraffic = false;
  let firstError: CheckOutput['firstError'] = null;
  const outOfScope: string[] = [];
  let section: 'errors' | 'warnings' | 'outside' | null = null;
  for (const line of lines.slice(start + 1)) {
    if (/\bErrors \(\d+\)/u.test(line)) section = 'errors';
    else if (/\bWarnings \(\d+\)/u.test(line)) section = 'warnings';
    else if (line.includes('outside the scope (not scanned)')) section = 'outside';
    else if (line.startsWith('Add an origin to scope.origins')) section = null;
    else if (line.includes('origin in scope')) section = null;
    const diagnostic = DIAGNOSTIC.exec(line);
    if (diagnostic !== null) {
      const code = diagnostic[1] as string;
      if (code === 'NO_TRAFFIC' || code === 'SCOPE_EMPTY') noTraffic = true;
      if (section === 'errors' && firstError === null)
        firstError = { code, message: diagnostic[2] as string };
    }
    if (section === 'outside') {
      const origin = ORIGIN.exec(line)?.[0];
      if (origin !== undefined && !outOfScope.includes(origin)) outOfScope.push(origin);
    }
    const word = VERDICT.exec(line)?.[1];
    if (word === 'NOT READY') {
      verdict = 'not-ready';
      if (line.includes('NO_TRAFFIC')) noTraffic = true;
    } else if (word === 'READY WITH WARNINGS') verdict = 'warnings';
    else if (word === 'READY') verdict = 'ready';
  }
  return verdict === null ? null : { verdict, noTraffic, firstError, outOfScope };
}
