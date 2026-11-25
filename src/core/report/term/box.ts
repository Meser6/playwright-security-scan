// Copied from playwright-performance-regression src/console/box.ts (MIT, same author); spec 04-REQ-05.
// The spec IDs in the comments below are those of the perf specification.
// Frames and tables of the console output (04-REQ-65, 09-REQ-27): rounded boxes with an optional
// title and word wrapping, and tables with box-drawing lines. TERM=dumb gets ASCII frames
// (`+`, `-`, `|`) and no emoji. Shared by the start banner, the run summary, the check output and
// the init wizard. Pure.
import { paint } from './color.ts';
import type { ColorStyle } from './color.ts';
import { clusters, padEnd, padStart, textWidth, truncateMiddle } from './text.ts';

export interface BoxOptions {
  /** Terminal width; the frame is at most this wide. */
  width: number;
  color: boolean;
  /** TERM=dumb: `+`, `-`, `|` and no emoji (04-REQ-65, 09-REQ-27). */
  ascii: boolean;
  /** Color of the frame. */
  border: ColorStyle;
  /** Title in the top edge, bold. */
  title?: string;
  /** Wrap long lines at spaces instead of cutting them with "…" (09-REQ-27). */
  wrap?: boolean;
}

/** A piece of a line in one style. */
export interface Span {
  text: string;
  style?: ColorStyle;
}

/** One line of a box: `text` in `style`, or several `spans`. */
export interface BoxLine {
  text?: string;
  style?: ColorStyle;
  spans?: readonly Span[];
  /** Indent of the continuation lines when wrapped. */
  indent?: number;
}

/** Whether the terminal only takes plain ASCII frames (TERM=dumb, 04-REQ-65). */
export function asciiTerminal(env: Readonly<Record<string, string | undefined>>): boolean {
  return env.TERM === 'dumb';
}

/**
 * Status marks (09-REQ-27): emoji, or text marks for TERM=dumb. Frames take no U+FE0F sequences
 * (09-D-23): terminals disagree on the width of ⚠️, but all show ⚠ in one column and ✅ ❌ in two.
 */
export interface Marks {
  ok: string;
  warn: string;
  error: string;
}

export function marks(ascii: boolean): Marks {
  return ascii ? { ok: '✔', warn: '!', error: '✖' } : { ok: '✅', warn: '⚠', error: '❌' };
}

interface Cell {
  char: string;
  style: ColorStyle | undefined;
  width: number;
}

function cellsOf(line: BoxLine): Cell[] {
  const spans = line.spans ?? [{ text: line.text ?? '', style: line.style }];
  const cells: Cell[] = [];
  for (const span of spans) {
    // One cell per cluster, so an emoji sequence is never cut or wrapped apart (text.ts).
    for (const c of clusters(span.text))
      cells.push({ char: c.text, style: span.style, width: c.width });
  }
  return cells;
}

function widthOf(cells: readonly Cell[]): number {
  return cells.reduce((sum, c) => sum + c.width, 0);
}

/** Cuts the cells to `width` columns with "…" at the end. */
function cutCells(cells: Cell[], width: number): Cell[] {
  if (widthOf(cells) <= width) return cells;
  const out: Cell[] = [];
  let used = 0;
  for (const cell of cells) {
    if (used + cell.width > width - 1) break;
    out.push(cell);
    used += cell.width;
  }
  out.push({ char: '…', style: out[out.length - 1]?.style, width: 1 });
  return out;
}

/** Word wrap at spaces; a word longer than the line is broken. */
function wrapCells(cells: Cell[], width: number, indent: number): Cell[][] {
  const lines: Cell[][] = [];
  const pad: Cell[] = Array.from({ length: indent }, () => ({
    char: ' ',
    style: undefined,
    width: 1,
  }));
  let rest = cells;
  for (let first = true; ; first = false) {
    const room = Math.max(1, first ? width : width - indent);
    let used = 0;
    let i = 0;
    let space = -1;
    while (i < rest.length && used + (rest[i]?.width ?? 0) <= room) {
      if (rest[i]?.char === ' ') space = i;
      used += rest[i]?.width ?? 0;
      i += 1;
    }
    const lead = first ? [] : pad;
    if (i >= rest.length) {
      lines.push([...lead, ...rest]);
      return lines;
    }
    const cut = rest[i]?.char === ' ' ? i : space > 0 ? space : Math.max(1, i);
    lines.push([...lead, ...rest.slice(0, cut)]);
    rest = rest.slice(cut);
    while (rest[0]?.char === ' ') rest = rest.slice(1);
    if (rest.length === 0) return lines;
  }
}

function render(cells: readonly Cell[], color: boolean): string {
  let out = '';
  let run = '';
  let style: ColorStyle | undefined;
  const flush = (): void => {
    out += style === undefined ? run : paint(run, style, color);
    run = '';
  };
  for (const cell of cells) {
    if (cell.style !== style) {
      flush();
      style = cell.style;
    }
    run += cell.char;
  }
  flush();
  return out;
}

/** A framed block as lines without newlines. */
export function boxLines(lines: readonly BoxLine[], opts: BoxOptions): string[] {
  const g = opts.ascii
    ? { tl: '+', tr: '+', bl: '+', br: '+', h: '-', v: '|' }
    : { tl: '╭', tr: '╮', bl: '╰', br: '╯', h: '─', v: '│' };
  const all = lines.map(cellsOf);
  const title = opts.title ?? '';
  const titleWidth = title === '' ? 0 : textWidth(title) + 3;
  const longest = Math.max(titleWidth, ...all.map(widthOf));
  const inner = Math.max(1, Math.min(longest, opts.width - 4));
  const border = (text: string): string => paint(text, opts.border, opts.color);
  const top =
    title === ''
      ? border(`${g.tl}${g.h.repeat(inner + 2)}${g.tr}`)
      : `${border(`${g.tl}${g.h} `)}${paint(title, 'bold', opts.color)}${border(
          ` ${g.h.repeat(Math.max(0, inner + 2 - titleWidth))}${g.tr}`,
        )}`;
  const out = [top];
  all.forEach((cells, index) => {
    const parts =
      opts.wrap === true
        ? wrapCells(cells, inner, lines[index]?.indent ?? 0)
        : [cutCells(cells, inner)];
    for (const part of parts) {
      const fill = ' '.repeat(Math.max(0, inner - widthOf(part)));
      out.push(`${border(g.v)} ${render(part, opts.color)}${fill} ${border(g.v)}`);
    }
  });
  out.push(border(`${g.bl}${g.h.repeat(inner + 2)}${g.br}`));
  return out;
}

/** A framed block; every line ends with a newline. */
export function box(lines: readonly BoxLine[], opts: BoxOptions): string {
  return `${boxLines(lines, opts).join('\n')}\n`;
}

export interface TableColumn {
  header: string;
  /** Numbers right, text left (09-REQ-27). */
  align?: 'left' | 'right';
  /** Takes the remaining width, at least `minWidth`; longer text is shortened in the middle. */
  flex?: boolean;
  minWidth?: number;
  /** Style of the cells of this column when the row has none (e.g. bold labels). */
  style?: ColorStyle;
}

export interface TableRow {
  cells: readonly string[];
  /** Style of the cell text; the lines stay dim. */
  style?: ColorStyle;
  /** Style per cell, before `style` (e.g. a colored marker, 10, chapter 9.1). */
  cellStyles?: readonly (ColorStyle | undefined)[];
}

export interface TableOptions {
  /** The table with its lines fits this width when the flexible column allows it. */
  width: number;
  color: boolean;
  ascii: boolean;
  /** Color of the lines; dim by default (09-REQ-27). */
  border?: ColorStyle;
  /** Header row with its separating line; true by default. */
  header?: boolean;
  /** Bold title in the top edge, like a box title (the start banner, 04-REQ-65). */
  title?: string;
}

/** Cuts `text` to `width` columns with "…" at the end; clusters are never split. */
function cutText(text: string, width: number): string {
  if (textWidth(text) <= width) return text;
  let out = '';
  let used = 0;
  for (const c of clusters(text)) {
    if (used + c.width > width - 1) break;
    out += c.text;
    used += c.width;
  }
  return `${out}…`;
}

/**
 * A table with box-drawing lines and a separated header row, as lines without newlines
 * (09-REQ-27, 09-D-24).
 */
export function table(
  columns: readonly TableColumn[],
  rows: readonly TableRow[],
  opts: TableOptions,
): string[] {
  const g = opts.ascii
    ? { v: '|', h: '-', top: ['+', '+', '+'], mid: ['+', '+', '+'], bottom: ['+', '+', '+'] }
    : { v: '│', h: '─', top: ['┌', '┬', '┐'], mid: ['├', '┼', '┤'], bottom: ['└', '┴', '┘'] };
  const header = opts.header !== false;
  const natural = columns.map((c, i) =>
    Math.max(header ? textWidth(c.header) : 0, ...rows.map((r) => textWidth(r.cells[i] ?? ''))),
  );
  const overhead = 3 * columns.length + 1;
  const widths = columns.map((c, i) => {
    if (c.flex !== true) return natural[i] ?? 0;
    const others = natural.reduce((sum, w, j) => (j === i ? sum : sum + w), 0);
    return Math.max(c.minWidth ?? 1, Math.min(natural[i] ?? 0, opts.width - overhead - others));
  });
  // A title in the top edge: "─ title " and at least one "─" after it; the last column widens
  // for it up to the terminal width, beyond that the title is cut.
  let title = opts.title ?? '';
  if (title !== '') {
    const inner = (): number => widths.reduce((sum, w) => sum + w + 3, -1);
    const room = Math.max(1, opts.width - 2 - 4);
    title = cutText(title, room);
    const need = textWidth(title) + 4 - inner();
    const last = widths.length - 1;
    if (need > 0 && last >= 0) widths[last] = (widths[last] ?? 0) + need;
  }
  const border = opts.border ?? 'dim';
  const edge = (text: string): string => paint(text, border, opts.color);
  const ruleText = ([left, cross, right]: string[]): string =>
    `${left}${widths.map((w) => g.h.repeat(w + 2)).join(cross)}${right}`;
  const rule = (marks: string[]): string => edge(ruleText(marks));
  const top = (): string => {
    if (title === '') return rule(g.top);
    // Every character of a rule is one column wide, so the rest of it is a plain slice.
    const rest = ruleText(g.top).slice(textWidth(title) + 4);
    return `${edge(`${g.top[0] ?? ''}${g.h} `)}${paint(title, 'bold', opts.color)}${edge(` ${rest}`)}`;
  };
  const line = (
    cells: readonly string[],
    style: ColorStyle | undefined,
    cellStyles: readonly (ColorStyle | undefined)[] = [],
  ): string => {
    const texts = columns.map((c, i) => {
      const w = widths[i] ?? 0;
      const raw = cells[i] ?? '';
      const text = c.flex === true ? truncateMiddle(raw, w) : raw;
      const padded = c.align === 'right' ? padStart(text, w) : padEnd(text, w);
      const cellStyle = cellStyles[i] ?? style ?? c.style;
      return cellStyle === undefined ? padded : paint(padded, cellStyle, opts.color);
    });
    return `${edge(g.v)} ${texts.join(` ${edge(g.v)} `)} ${edge(g.v)}`;
  };
  return [
    top(),
    ...(header
      ? [
          line(
            columns.map((c) => c.header),
            'bold',
          ),
          rule(g.mid),
        ]
      : []),
    ...rows.map((r) => line(r.cells, r.style, r.cellStyles)),
    rule(g.bottom),
  ];
}
