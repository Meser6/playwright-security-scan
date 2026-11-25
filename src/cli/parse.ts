// Arguments of the binary (11-REQ-01): the package has no commands and no options. Without
// arguments the binary runs the wizard; any argument is CLI_UNKNOWN_COMMAND. Pure.
import { INIT_COMMAND } from './constants.ts';
import type { CliIssue, Result } from './constants.ts';

export type ParsedCommand = { kind: 'init' };

/** The message and hint for arguments given to the binary or to the create package. */
export function noArgumentsIssue(args: readonly string[]): CliIssue {
  return {
    code: 'CLI_UNKNOWN_COMMAND',
    message: `The package has no commands or options, got "${args.join(' ')}".`,
    hint: [
      'Run your test command with PW_SEC_MODE, e.g. PW_SEC_MODE=scan <your test command>',
      '(check, baseline or scan). Set up with ' +
        `${INIT_COMMAND}; its variables are PW_SEC_LANG, PW_SEC_DRY_RUN and PW_SEC_NO_TUTORIAL.`,
    ].join('\n'),
  };
}

/** Parses the arguments after the command name (`process.argv.slice(2)`). */
export function parseArgs(argv: readonly string[]): Result<ParsedCommand, CliIssue> {
  if (argv.length === 0) return { ok: true, value: { kind: 'init' } };
  return { ok: false, issues: [noArgumentsIssue(argv)] };
}
