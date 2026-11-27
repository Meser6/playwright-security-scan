// Fake wizard host: captured streams, a scripted check child process and signal handlers.
import { EventEmitter } from 'node:events';
import { mkdir, readdir, readFile, realpath, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import type {
  ChildProcessLike,
  CliHost,
  ForwardedSignal,
  Prompt,
  ProcessOptions,
} from '../../../src/cli/host.ts';

export class FakeChild extends EventEmitter implements ChildProcessLike {
  readonly kills: (NodeJS.Signals | undefined)[] = [];
  readonly stdout = new EventEmitter();
  readonly stderr = new EventEmitter();

  kill(signal?: NodeJS.Signals): boolean {
    this.kills.push(signal);
    return true;
  }

  /** Prints `text` on stdout of the run. */
  print(text: string): void {
    this.stdout.emit('data', Buffer.from(text));
  }

  exit(code: number | null, signal: NodeJS.Signals | null = null): void {
    this.emit('close', code, signal);
  }
}

export interface FakeHost {
  host: CliHost;
  stdout: string[];
  stderr: string[];
  spawned: { file?: string; args: string[]; options: ProcessOptions }[];
  child: FakeChild;
  signals: Map<ForwardedSignal, (() => void)[]>;
  /** Sends a signal to the wizard. */
  signal(name: ForwardedSignal): void;
  /** Directory @playwright/test was resolved from. */
  resolvedFrom?: string;
  /** Files written through the host, in order. */
  written: string[];
}

export interface FakeHostOptions {
  cwd: string;
  env?: Record<string, string>;
  /** null: @playwright/test is not installed. */
  playwright?: { cliPath: string; version: string } | null;
  /** Called when the check process is started: the script of the run (exit). */
  onSpawn?: (fake: FakeHost, options: ProcessOptions) => void;
  platform?: string;
  /** Terminal questions (init); without it the host has no terminal. */
  prompt?: () => Prompt;
  /** process.stdout.columns of the host (unset: not reported). */
  columns?: number;
}

export function fakeCliHost(options: FakeHostOptions): FakeHost {
  const signals = new Map<ForwardedSignal, (() => void)[]>();
  const fake: FakeHost = {
    stdout: [],
    stderr: [],
    spawned: [],
    child: new FakeChild(),
    signals,
    signal: (name) => {
      for (const handler of [...(signals.get(name) ?? [])]) handler();
    },
    host: undefined as unknown as CliHost,
    written: [],
  };
  fake.host = {
    cwd: options.cwd,
    paths: { join, resolve, dirname },
    env: options.env ?? {},
    platform: options.platform ?? 'linux',
    execPath: '/usr/bin/node',
    stdin: { isTTY: options.prompt !== undefined },
    stdout: {
      write: (t: string) => fake.stdout.push(t),
      isTTY: options.prompt !== undefined,
      ...(options.columns === undefined ? {} : { columns: options.columns }),
    },
    stderr: { write: (t: string) => fake.stderr.push(t) },
    minPlaywrightVersion: '1.57.0',
    resolvePlaywright: (dir) => {
      fake.resolvedFrom = dir;
      return options.playwright === undefined
        ? { cliPath: '/project/node_modules/@playwright/test/cli.js', version: '1.57.0' }
        : options.playwright;
    },
    spawnProcess: (file, args, spawnOptions) => {
      fake.spawned.push({ file, args, options: spawnOptions });
      // The wizard's check run (11-REQ-10) ends with 0 unless the test decides.
      setImmediate(() =>
        options.onSpawn === undefined ? fake.child.exit(0) : options.onSpawn(fake, spawnOptions),
      );
      return fake.child;
    },
    onSignal: (signal, handler) => {
      signals.set(signal, [...(signals.get(signal) ?? []), handler]);
      return () => {
        signals.set(
          signal,
          (signals.get(signal) ?? []).filter((h) => h !== handler),
        );
      };
    },
    readText: async (path) => {
      try {
        return await readFile(path, 'utf8');
      } catch {
        return null;
      }
    },
    realPath: async (path) => {
      try {
        return await realpath(path);
      } catch {
        return null;
      }
    },
    listDir: async (path) => {
      try {
        return (await readdir(path, { withFileTypes: true }))
          .map((e) => ({ name: e.name, directory: e.isDirectory() }))
          .sort((a, b) => (a.name < b.name ? -1 : 1));
      } catch {
        return [];
      }
    },
    writeText: async (path, text) => {
      fake.written.push(path);
      await mkdir(dirname(path), { recursive: true });
      await writeFile(path, text);
    },
    createPrompt: () => {
      if (options.prompt === undefined) throw new Error('no terminal');
      return options.prompt();
    },
  };
  return fake;
}
