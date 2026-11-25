// Text scanning of JavaScript and TypeScript sources for the init wizard (perf 04-REQ-39, perf 04-D-17,
// perf 04-D-18): bracket matching that skips strings, template literals, comments and regular
// expression literals. No parser: an unusual layout makes the caller fall back to a manual
// instruction instead of a change. Pure.

const OPEN: Record<string, string> = { '(': ')', '[': ']', '{': '}' };
const CLOSE = new Set([')', ']', '}']);
/** After these characters a "/" starts a regular expression literal, not a division. */
const REGEX_BEFORE = new Set([
  '',
  '(',
  ',',
  '=',
  ':',
  '[',
  '!',
  '&',
  '|',
  '?',
  '{',
  '}',
  ';',
  '+',
  '-',
  '*',
  '%',
  '<',
  '>',
  '~',
  '^',
]);

/** Index after the string or template literal that starts at `i`. */
function skipString(text: string, i: number): number {
  const quote = text[i];
  let j = i + 1;
  while (j < text.length) {
    const c = text[j];
    if (c === '\\') {
      j += 2;
      continue;
    }
    if (c === quote) return j + 1;
    if (quote === '`' && c === '$' && text[j + 1] === '{') {
      const end = matchBracket(text, j + 1);
      if (end === -1) return text.length;
      j = end;
      continue;
    }
    if (quote !== '`' && c === '\n') return j;
    j += 1;
  }
  return text.length;
}

/** Index after the regular expression literal that starts at `i`. */
function skipRegex(text: string, i: number): number {
  let j = i + 1;
  let inClass = false;
  while (j < text.length) {
    const c = text[j];
    if (c === '\\') {
      j += 2;
      continue;
    }
    if (c === '\n') return j;
    if (inClass) {
      if (c === ']') inClass = false;
    } else if (c === '[') {
      inClass = true;
    } else if (c === '/') {
      j += 1;
      while (j < text.length && /[a-z]/u.test(text[j] as string)) j += 1;
      return j;
    }
    j += 1;
  }
  return text.length;
}

/**
 * Index after a comment, string, template or regular expression literal starting at `i`, or `i`
 * when none starts there. `previous` is the last significant character before `i`.
 */
export function skipNonCode(text: string, i: number, previous: string): number {
  const c = text[i];
  const next = text[i + 1];
  if (c === '/' && next === '/') {
    const end = text.indexOf('\n', i);
    return end === -1 ? text.length : end;
  }
  if (c === '/' && next === '*') {
    const end = text.indexOf('*/', i + 2);
    return end === -1 ? text.length : end + 2;
  }
  if (c === '"' || c === "'" || c === '`') return skipString(text, i);
  if (c === '/' && REGEX_BEFORE.has(previous)) return skipRegex(text, i);
  return i;
}

/**
 * Index just after the bracket that closes the one at `open` ("(", "[" or "{"), or -1 when the
 * brackets do not balance.
 */
export function matchBracket(text: string, open: number): number {
  const stack: string[] = [];
  let previous = '';
  let i = open;
  while (i < text.length) {
    const skipped = skipNonCode(text, i, previous);
    if (skipped !== i) {
      i = skipped;
      previous = 'x';
      continue;
    }
    const c = text[i] as string;
    if (OPEN[c] !== undefined) {
      stack.push(OPEN[c] as string);
    } else if (CLOSE.has(c)) {
      if (stack.pop() !== c) return -1;
      if (stack.length === 0) return i + 1;
    }
    if (!/\s/u.test(c)) previous = /[\w$]/u.test(c) ? 'x' : c;
    i += 1;
  }
  return -1;
}

/**
 * Index of the "(" of a call whose callee ends at `from`, skipping type arguments
 * (`base.extend<{ a: () => void }>(`), or -1 when no call follows.
 */
export function callParen(text: string, from: number): number {
  let i = from;
  while (/\s/u.test(text[i] ?? '')) i += 1;
  if (text[i] === '<') {
    let depth = 0;
    for (; i < text.length; i += 1) {
      const c = text[i];
      if (c === '<' || c === '{' || c === '(' || c === '[') depth += 1;
      else if (c === '}' || c === ')' || c === ']') depth -= 1;
      else if (c === '>' && text[i - 1] !== '=') {
        depth -= 1;
        if (depth === 0) break;
      }
    }
    i += 1;
    while (/\s/u.test(text[i] ?? '')) i += 1;
  }
  return text[i] === '(' ? i : -1;
}

/** Whether only whitespace, comments and at most one ";" follow index `i`. */
export function onlyTrailing(text: string, i: number): boolean {
  let semicolon = false;
  let j = i;
  while (j < text.length) {
    const c = text[j] as string;
    if (/\s/u.test(c)) {
      j += 1;
    } else if (c === ';' && !semicolon) {
      semicolon = true;
      j += 1;
    } else if (c === '/' && (text[j + 1] === '/' || text[j + 1] === '*')) {
      j = skipNonCode(text, j, '');
    } else {
      return false;
    }
  }
  return true;
}

/** Whether the statement ends after index `i` (";", a line break or the end of the file). */
export function statementEnds(text: string, i: number): boolean {
  return /^[ \t]*(?:;|\r?\n|$|\/\/)/u.test(text.slice(i, i + 200));
}

const IMPORT_DONE = /(?:\bfrom\s*(['"])[^'"\n]+\1|^\s*import\s*(['"])[^'"\n]+\2)\s*;?\s*$/u;
const REQUIRE_DONE = /\brequire\(\s*(['"])[^'"\n]+\1\s*\)(?:\.[\w$]+)*\s*;?\s*$/u;

/**
 * Offset at which new import statements go: after the last import or top-level `require()`
 * statement at the start of the file, else after the leading comments.
 */
export function importInsertOffset(text: string): number {
  let offset = 0;
  let lastImportEnd = -1;
  let leadingEnd = 0;
  let seenCode = false;
  let inComment = false;
  let pending: { done: RegExp; text: string } | null = null;
  for (const line of text.split('\n')) {
    const start = offset;
    const end = Math.min(offset + line.length + 1, text.length);
    offset += line.length + 1;
    const trimmed = line.trim();
    if (pending !== null) {
      pending.text += `\n${line}`;
      if (pending.done.test(pending.text)) {
        pending = null;
        lastImportEnd = end;
      }
      continue;
    }
    const header = !seenCode;
    if (inComment || trimmed.startsWith('//') || trimmed.startsWith('/*')) {
      if (inComment) inComment = !trimmed.includes('*/');
      else if (trimmed.startsWith('/*')) inComment = !trimmed.includes('*/');
      if (header) leadingEnd = end;
      continue;
    }
    if (trimmed === '') continue;
    if (/^['"]use strict['"];?$/u.test(trimmed)) {
      leadingEnd = end;
      continue;
    }
    let done: RegExp | null = null;
    if (/^import[\s{'"*]/u.test(trimmed)) done = IMPORT_DONE;
    else if (
      /^(?:const|let|var)\b/u.test(trimmed) &&
      /\brequire\(\s*['"]/u.test(text.slice(start, end + 300).split(';')[0] ?? '')
    ) {
      done = REQUIRE_DONE;
    }
    if (done === null) break;
    seenCode = true;
    if (done.test(line)) lastImportEnd = end;
    else pending = { done, text: line };
  }
  return lastImportEnd >= 0 ? lastImportEnd : leadingEnd;
}

/** `text` with `lines` inserted as whole lines at the import position. */
export function addImports(text: string, lines: readonly string[]): string {
  if (lines.length === 0) return text;
  const at = importInsertOffset(text);
  const before = text.slice(0, at);
  const block = `${lines.join('\n')}\n`;
  const sep = before === '' || before.endsWith('\n') ? '' : '\n';
  return `${before}${sep}${block}${text.slice(at)}`;
}
