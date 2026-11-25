// Copied from playwright-performance-regression src/console/text.ts (MIT, same author); spec 04-REQ-05.
// The spec IDs in the comments below are those of the perf specification.
// Text helpers of the console output (01, chapter 4.9): widths in terminal columns, padding,
// truncation in the middle and plurals.

/** Code unit order, never localeCompare (02-REQ-04). */
export function compareText(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

export function plural(n: number, word: string, many = `${word}s`): string {
  return `${n} ${n === 1 ? word : many}`;
}

/** Shortens text to `width` terminal columns with "…" in the middle (01, chapter 4.9). */
export function truncateMiddle(text: string, width: number): string {
  if (textWidth(text) <= width) return text;
  if (width <= 1) return '…'.slice(0, width);
  const chars = clusters(text);
  const headRoom = Math.ceil((width - 1) / 2);
  const tailRoom = width - 1 - headRoom;
  let head = '';
  let used = 0;
  for (const c of chars) {
    if (used + c.width > headRoom) break;
    head += c.text;
    used += c.width;
  }
  let tail = '';
  used = 0;
  for (let i = chars.length - 1; i >= 0; i -= 1) {
    const c = chars[i];
    if (c === undefined || used + c.width > tailRoom) break;
    tail = c.text + tail;
    used += c.width;
  }
  return `${head}…${tail}`;
}

// Characters shown as emoji (two terminal columns) without a variation selector
// (Emoji_Presentation=Yes, East Asian Width W): ✅ ❌ ⏳ ⭐ and the pictographs from U+1F300. Other
// characters take one column (09-REQ-27, 09-D-23).
const WIDE: readonly (readonly [number, number])[] = [
  [0x231a, 0x231b],
  [0x23e9, 0x23ec],
  [0x23f0, 0x23f0],
  [0x23f3, 0x23f3],
  [0x25fd, 0x25fe],
  [0x2614, 0x2615],
  [0x2648, 0x2653],
  [0x267f, 0x267f],
  [0x2693, 0x2693],
  [0x26a1, 0x26a1],
  [0x26aa, 0x26ab],
  [0x26bd, 0x26be],
  [0x26c4, 0x26c5],
  [0x26ce, 0x26ce],
  [0x26d4, 0x26d4],
  [0x26ea, 0x26ea],
  [0x26f2, 0x26f3],
  [0x26f5, 0x26f5],
  [0x26fa, 0x26fa],
  [0x26fd, 0x26fd],
  [0x2705, 0x2705],
  [0x270a, 0x270b],
  [0x2728, 0x2728],
  [0x274c, 0x274c],
  [0x274e, 0x274e],
  [0x2753, 0x2755],
  [0x2757, 0x2757],
  [0x2795, 0x2797],
  [0x27b0, 0x27b0],
  [0x27bf, 0x27bf],
  [0x2b1b, 0x2b1c],
  [0x2b50, 0x2b50],
  [0x2b55, 0x2b55],
  [0x1f300, 0x1faff],
];

// Code points of no width of their own (wcwidth 0): combining marks, zero width space and joiners,
// variation selectors and the emoji keycap and skin tone modifiers.
const ZERO: readonly (readonly [number, number])[] = [
  [0x0300, 0x036f],
  [0x200b, 0x200d],
  [0x20d0, 0x20ff],
  [0xfe00, 0xfe0f],
  [0x1f3fb, 0x1f3ff],
  [0xe0100, 0xe01ef],
];

const VS16 = 0xfe0f;
const ZWJ = 0x200d;

function inRanges(cp: number, ranges: readonly (readonly [number, number])[]): boolean {
  return ranges.some(([from, to]) => cp >= from && cp <= to);
}

/** Terminal columns of one code point on its own: 2, 1 or 0 (09-REQ-27). */
export function charWidth(char: string): number {
  const cp = char.codePointAt(0) ?? 0;
  if (inRanges(cp, ZERO)) return 0;
  return inRanges(cp, WIDE) ? 2 : 1;
}

/** A character with its zero-width followers, never split when cutting or wrapping. */
export interface Cluster {
  text: string;
  width: number;
}

/**
 * Splits text into clusters of terminal columns (wcwidth conventions, 09-REQ-27): zero-width code
 * points join the cluster before them; U+FE0F makes it an emoji of two columns; after U+200D (ZWJ)
 * the next code point joins too, so a ZWJ sequence takes the columns of its first character.
 */
export function clusters(text: string): Cluster[] {
  const out: Cluster[] = [];
  let joined = false;
  for (const char of text) {
    const cp = char.codePointAt(0) ?? 0;
    const last = out[out.length - 1];
    if (last !== undefined && (joined || charWidth(char) === 0)) {
      last.text += char;
      if (cp === VS16) last.width = 2;
      joined = cp === ZWJ;
      continue;
    }
    out.push({ text: char, width: charWidth(char) });
    joined = false;
  }
  return out;
}

/** Terminal columns of `text` (09-REQ-27): wide characters and emoji sequences count as two. */
export function textWidth(text: string): number {
  return clusters(text).reduce((sum, c) => sum + c.width, 0);
}

export function padEnd(text: string, width: number): string {
  return text + ' '.repeat(Math.max(0, width - textWidth(text)));
}

export function padStart(text: string, width: number): string {
  return ' '.repeat(Math.max(0, width - textWidth(text))) + text;
}
