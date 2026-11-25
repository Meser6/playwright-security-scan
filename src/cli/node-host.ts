// The wizard host on Node (perf 04, chapter 6): process streams and signals, files, @playwright/test of
// the project and the check child process (perf 04-REQ-58, NF-05, V-03).
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { mkdir, mkdtemp, readdir, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';
import { MIN_PLAYWRIGHT_VERSION } from './constants.ts';
import type { CliHost, DirEntry, PlaywrightInstall } from './host.ts';
import { readlinePrompt } from './init/index.ts';

function isModuleNotFound(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    error.code === 'MODULE_NOT_FOUND'
  );
}

/**
 * @playwright/test resolved from `dir` (never from this package): the `bin.playwright` script of
 * its package.json. MODULE_NOT_FOUND means it is not installed.
 */
export function resolvePlaywright(dir: string): PlaywrightInstall | null {
  const require = createRequire(join(dir, 'noop.js'));
  let manifest: string;
  try {
    manifest = require.resolve('@playwright/test/package.json');
  } catch (error) {
    if (isModuleNotFound(error)) return null;
    throw error;
  }
  const pkg = JSON.parse(readFileSync(manifest, 'utf8')) as {
    version?: string;
    bin?: string | Record<string, string>;
  };
  const bin = typeof pkg.bin === 'string' ? pkg.bin : pkg.bin?.playwright;
  if (bin === undefined) throw new Error(`${manifest} has no "bin.playwright" entry`);
  return { cliPath: resolve(dirname(manifest), bin), version: pkg.version ?? '0.0.0' };
}

/** Text of a file, or null when it does not exist or is not readable. */
async function readTextFile(path: string): Promise<string | null> {
  try {
    return await readFile(path, 'utf8');
  } catch {
    return null;
  }
}

export function nodeHost(): CliHost {
  return {
    cwd: process.cwd(),
    paths: { join, resolve, dirname },
    env: process.env,
    platform: process.platform,
    execPath: process.execPath,
    stdin: process.stdin,
    stdout: process.stdout,
    stderr: process.stderr,
    minPlaywrightVersion: MIN_PLAYWRIGHT_VERSION,
    resolvePlaywright,
    spawnProcess: (file, args, options) => spawn(file, args, options),
    onSignal: (signal, handler) => {
      process.on(signal, handler);
      return () => {
        process.off(signal, handler);
      };
    },
    readText: readTextFile,
    realPath: async (path) => {
      try {
        return await realpath(path);
      } catch {
        return null;
      }
    },
    listDir: async (path): Promise<DirEntry[]> => {
      try {
        const entries = await readdir(path, { withFileTypes: true });
        return entries
          .map((e) => ({ name: e.name, directory: e.isDirectory() }))
          .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
      } catch {
        return [];
      }
    },
    writeText: async (path, text) => {
      await mkdir(dirname(path), { recursive: true });
      await writeFile(path, text, 'utf8');
    },
    makeTempDir: (prefix) => mkdtemp(join(tmpdir(), prefix)),
    removeDir: (path) => rm(path, { recursive: true, force: true }),
    createPrompt: () => readlinePrompt(process.stdin, process.stdout),
  };
}
