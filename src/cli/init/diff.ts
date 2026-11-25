// Unified diff of a planned file change (perf 04-REQ-38 step 7, perf 04-REQ-39): shown before each
// confirmation and used for the golden files of init (12, chapter 8). Pure.
import type { FileChange } from './plan.ts';

const CONTEXT = 3;

type Op = { kind: ' ' | '-' | '+'; line: string };

function lines(text: string): string[] {
  if (text === '') return [];
  const parts = text.split('\n');
  if (parts[parts.length - 1] === '') parts.pop();
  return parts;
}

/** Line operations from `a` to `b`: common prefix and suffix, LCS for the middle. */
function operations(a: string[], b: string[]): Op[] {
  let start = 0;
  while (start < a.length && start < b.length && a[start] === b[start]) start += 1;
  let endA = a.length;
  let endB = b.length;
  while (endA > start && endB > start && a[endA - 1] === b[endB - 1]) {
    endA -= 1;
    endB -= 1;
  }
  const midA = a.slice(start, endA);
  const midB = b.slice(start, endB);
  const n = midA.length;
  const m = midB.length;
  // at(i, j): length of the LCS of midA[i..] and midB[j..].
  const lcs = new Uint32Array((n + 1) * (m + 1));
  const at = (i: number, j: number): number => lcs[i * (m + 1) + j] as number;
  for (let i = n - 1; i >= 0; i -= 1) {
    for (let j = m - 1; j >= 0; j -= 1) {
      lcs[i * (m + 1) + j] =
        midA[i] === midB[j] ? at(i + 1, j + 1) + 1 : Math.max(at(i + 1, j), at(i, j + 1));
    }
  }
  const ops: Op[] = a.slice(0, start).map((line) => ({ kind: ' ', line }));
  let i = 0;
  let j = 0;
  while (i < n || j < m) {
    if (i < n && j < m && midA[i] === midB[j]) {
      ops.push({ kind: ' ', line: midA[i] as string });
      i += 1;
      j += 1;
    } else if (i < n && (j === m || at(i + 1, j) >= at(i, j + 1))) {
      ops.push({ kind: '-', line: midA[i] as string });
      i += 1;
    } else {
      ops.push({ kind: '+', line: midB[j] as string });
      j += 1;
    }
  }
  for (const line of a.slice(endA)) ops.push({ kind: ' ', line });
  return ops;
}

/** Unified diff with 3 lines of context; empty when the texts are equal. */
export function unifiedDiff(change: FileChange): string {
  const before = change.before ?? '';
  if (before === change.after) return '';
  const ops = operations(lines(before), lines(change.after));
  const out = [
    change.before === null ? '--- /dev/null' : `--- a/${change.path}`,
    `+++ b/${change.path}`,
  ];
  // Group changed operations with their context into hunks.
  const changed = ops.flatMap((op, index) => (op.kind === ' ' ? [] : [index]));
  let h = 0;
  while (h < changed.length) {
    const first = Math.max(0, (changed[h] as number) - CONTEXT);
    let last = Math.min(ops.length - 1, (changed[h] as number) + CONTEXT);
    h += 1;
    while (h < changed.length && (changed[h] as number) - CONTEXT <= last + 1) {
      last = Math.min(ops.length - 1, (changed[h] as number) + CONTEXT);
      h += 1;
    }
    let oldStart = 1;
    let newStart = 1;
    for (const op of ops.slice(0, first)) {
      if (op.kind !== '+') oldStart += 1;
      if (op.kind !== '-') newStart += 1;
    }
    const hunk = ops.slice(first, last + 1);
    const oldCount = hunk.filter((op) => op.kind !== '+').length;
    const newCount = hunk.filter((op) => op.kind !== '-').length;
    out.push(
      `@@ -${oldCount === 0 ? oldStart - 1 : oldStart},${oldCount} +${newCount === 0 ? newStart - 1 : newStart},${newCount} @@`,
    );
    for (const op of hunk) out.push(`${op.kind}${op.line}`);
  }
  return `${out.join('\n')}\n`;
}
