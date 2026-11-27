// A filtered run (04-REQ-03): --grep, --grep-invert, --project, file arguments, --only-changed
// or --last-failed. A baseline run then keeps resolved entries. --shard is no filter (17-REQ-06):
// a shard run writes a shard file and the merge decides. test.only cannot be
// detected with public APIs (P-11); the documentation warns about it.
import type { FullConfig, Suite } from '@playwright/test/reporter';

const VALUE_OPTIONS = new Set([
  '--shard',
  '-c',
  '--config',
  '--reporter',
  '-j',
  '--workers',
  '--retries',
  '--timeout',
  '--repeat-each',
  '--max-failures',
  '--output',
  '--trace',
  '--tsconfig',
  '--global-timeout',
  '--browser',
  '--ui-host',
  '--ui-port',
]);
const FILTER_OPTIONS = [
  '-g',
  '--grep',
  '--grep-invert',
  '--project',
  '--only-changed',
  '--last-failed',
];

/** Whether the run covers only part of the tests. */
export function isPartialRun(
  _config: FullConfig | undefined,
  _suite: Suite | undefined,
  argv: readonly string[],
): boolean {
  const start = argv.findIndex((a) => a === 'test');
  const args = start < 0 ? [] : argv.slice(start + 1);
  for (let i = 0; i < args.length; i++) {
    const arg = args[i] ?? '';
    const name = arg.split('=')[0] ?? '';
    if (FILTER_OPTIONS.includes(name)) return true;
    if (arg.startsWith('-')) {
      if (VALUE_OPTIONS.has(name) && !arg.includes('=')) i += 1;
      continue;
    }
    return true; // a file or line filter
  }
  return false;
}
