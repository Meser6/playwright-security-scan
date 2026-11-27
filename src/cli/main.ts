// Entry logic of the binary (11-REQ-01): without arguments it runs the wizard (or, with
// PW_SEC_MODE=merge, the shard merge of 17), with arguments it prints CLI_UNKNOWN_COMMAND. Every error is caught at this
// boundary and ends with exit code 3 (01, chapter 8).
import type { Issue } from './constants.ts';
import { readInitEnv } from './env.ts';
import type { CliHost } from './host.ts';
import { runInit } from './init/index.ts';
import { LANGUAGES } from './init/messages.ts';
import type { WizardLanguage } from './init/messages.ts';
import { formatIssues, outputStyle } from './output.ts';
import { parseArgs } from './parse.ts';
import { runMerge } from '../merge/index.ts';
import { isMergeMode } from '../mode/index.ts';

function color(host: CliHost): { color: boolean } {
  return outputStyle(host.stderr, host.env);
}

function internalError(error: unknown): Issue {
  const text = error instanceof Error ? (error.stack ?? error.message) : String(error);
  return {
    code: 'CLI_INTERNAL_ERROR',
    message: `Unexpected error in the CLI: ${text}`,
    hint: 'This is a bug in the package; please report it with the message above.',
  };
}

/** Runs the binary with `argv` (the arguments after the command name); returns the exit code. */
export async function main(argv: readonly string[], host: CliHost): Promise<number> {
  try {
    const parsed = parseArgs(argv);
    if (!parsed.ok) {
      host.stderr.write(formatIssues(parsed.issues, 'error', color(host)));
      return 3;
    }
    // PW_SEC_MODE=merge npx pw-sec: the shard merge instead of the wizard (17-REQ-09).
    if (isMergeMode(host.env)) return runMerge(host);
    const env = readInitEnv(host.env, LANGUAGES);
    if (!env.ok) {
      host.stderr.write(formatIssues(env.issues, 'error', color(host)));
      return 3;
    }
    const { lang, dryRun, noTutorial } = env.value;
    return await runInit(
      {
        dryRun,
        ...(lang === undefined ? {} : { lang: lang as WizardLanguage }),
        ...(noTutorial ? { noTutorial: true } : {}),
      },
      host,
      color(host),
    );
  } catch (error) {
    host.stderr.write(formatIssues([internalError(error)], 'error', color(host)));
    return 3;
  }
}
