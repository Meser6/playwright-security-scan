// Test selection of a check (04-REQ-10), after the perf package: the first test of each file of
// the scanned projects runs, up to PW_SEC_MAX_TESTS tests; the others are skipped before their
// body. Workers run in parallel here (D-04), so each decision claims files with an exclusive create
// in a directory of the run: a claim either succeeds in exactly one worker or fails.
import { createHash } from 'node:crypto';
import { mkdirSync, openSync, closeSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/** `<tmpdir>/playwright-security-scan-<runId>.check` (04-REQ-10). */
export function checkStateDir(runId: string): string {
  return join(tmpdir(), `playwright-security-scan-${runId.replace(/[^A-Za-z0-9-]/g, '_')}.check`);
}

function claim(path: string): boolean {
  try {
    closeSync(openSync(path, 'wx'));
    return true;
  } catch {
    return false;
  }
}

/**
 * Whether the test runs in the check: the first test of its file that asks, while fewer than
 * `maxTests` tests got a slot.
 */
export function checkRunsTest(
  runId: string,
  maxTests: number,
  project: string,
  file: string,
): boolean {
  const dir = checkStateDir(runId);
  mkdirSync(dir, { recursive: true });
  const id = createHash('sha256').update(`${project}\u0000${file}`).digest('hex').slice(0, 32);
  if (!claim(join(dir, `file-${id}`))) return false;
  for (let slot = 0; slot < maxTests; slot++) {
    if (claim(join(dir, `slot-${slot}`))) return true;
  }
  return false;
}

/** Removes the claims after the run (04-REQ-10). */
export function removeCheckState(runId: string): void {
  rmSync(checkStateDir(runId), { recursive: true, force: true });
}
