// What the wizard needs from the process: streams, environment, files, signals and the check
// process. The Node implementation is in node-host.ts; tests pass fakes (perf 04, chapter 6: I/O and
// spawn only at the edge).

export interface Stream {
  write(text: string): unknown;
  isTTY?: boolean;
  columns?: number;
}

export type ForwardedSignal = 'SIGINT' | 'SIGTERM';

/** An output stream of the check child process. */
export interface ChildOutput {
  on(event: 'data', listener: (chunk: Buffer | string) => void): unknown;
}

/**
 * The check child process as the wizard uses it (perf 04-REQ-58). Its stdout and stderr are pipes:
 * the wizard shows them and reads the result of the check from stdout (11-REQ-11).
 */
export interface ChildProcessLike {
  stdout: ChildOutput | null;
  stderr: ChildOutput | null;
  kill(signal?: NodeJS.Signals): boolean;
  /** After the exit and the end of stdout and stderr. */
  once(
    event: 'close',
    listener: (code: number | null, signal: NodeJS.Signals | null) => void,
  ): unknown;
  once(event: 'error', listener: (error: Error) => void): unknown;
}

export interface ProcessOptions {
  cwd: string;
  env: Record<string, string>;
  stdio: ['inherit', 'pipe', 'pipe'];
  shell: boolean | string;
}

export interface PlaywrightInstall {
  /** Absolute path of the Playwright CLI script (`bin.playwright` of @playwright/test). */
  cliPath: string;
  version: string;
}

export interface PathHelpers {
  join: (a: string, b: string) => string;
  resolve: (a: string, b: string) => string;
  dirname: (path: string) => string;
}

/** One entry of a directory listing. */
export interface DirEntry {
  name: string;
  directory: boolean;
}

/** Questions in the terminal (init, perf 04-REQ-37). `ask` rejects with PromptAborted on Ctrl+C. */
export interface Prompt {
  ask(question: string): Promise<string>;
  close(): void;
}

export interface CliHost {
  cwd: string;
  paths: PathHelpers;
  env: Readonly<Record<string, string | undefined>>;
  platform: string;
  /** process.execPath: Node of this process. */
  execPath: string;
  stdin: { isTTY?: boolean };
  stdout: Stream;
  stderr: Stream;
  /** Lowest supported @playwright/test version (D-07). */
  minPlaywrightVersion: string;
  /** @playwright/test resolved from `dir`, or null when it is not installed there (V-03). */
  resolvePlaywright(dir: string): PlaywrightInstall | null;
  /**
   * child_process.spawn(file, args, options) for the wizard's check run (perf 04-REQ-58); `shell` is
   * true only for a checked script name on Windows.
   */
  spawnProcess(file: string, args: string[], options: ProcessOptions): ChildProcessLike;
  /** Registers a signal handler; returns the function that removes it. */
  onSignal(signal: ForwardedSignal, handler: () => void): () => void;
  /** Text of a file, or null when it does not exist. */
  readText(path: string): Promise<string | null>;
  /** The real path of a file or directory (links resolved), or null when it does not exist. */
  realPath(path: string): Promise<string | null>;
  /** Entries of a directory; empty when it does not exist. */
  listDir(path: string): Promise<DirEntry[]>;
  /** Writes a UTF-8 file, creating its directory. */
  writeText(path: string, text: string): Promise<void>;
  /** Terminal questions on stdin and stdout (init). */
  createPrompt(): Prompt;
}
