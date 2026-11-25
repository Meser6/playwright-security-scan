// Variables of the wizard (11-REQ-03): PW_SEC_LANG, PW_SEC_DRY_RUN and PW_SEC_NO_TUTORIAL. A
// value that is not allowed is an error before the first question. Pure.
import type { CliIssue, Result } from './constants.ts';

export const LANG_ENV = 'PW_SEC_LANG';
export const DRY_RUN_ENV = 'PW_SEC_DRY_RUN';
export const NO_TUTORIAL_ENV = 'PW_SEC_NO_TUTORIAL';

export interface InitEnv {
  dryRun: boolean;
  noTutorial: boolean;
  lang?: string;
}

function invalid(name: string, allowed: string, value: string, hint: string): CliIssue {
  return {
    code: 'INIT_INVALID_VALUE',
    message: `${name}=${JSON.stringify(value)} is not valid: expected ${allowed}.`,
    hint,
  };
}

function flag(
  env: Readonly<Record<string, string | undefined>>,
  name: string,
  hint: string,
  issues: CliIssue[],
): boolean {
  const value = (env[name] ?? '').trim();
  if (value === '') return false;
  if (value === '1') return true;
  issues.push(invalid(name, '1', value, hint));
  return false;
}

export function readInitEnv(
  env: Readonly<Record<string, string | undefined>>,
  languages: readonly string[],
): Result<InitEnv, CliIssue> {
  const issues: CliIssue[] = [];
  const state: InitEnv = {
    dryRun: flag(
      env,
      DRY_RUN_ENV,
      `Set ${DRY_RUN_ENV}=1 to only see the planned changes, or unset it.`,
      issues,
    ),
    noTutorial: flag(
      env,
      NO_TUTORIAL_ENV,
      `Set ${NO_TUTORIAL_ENV}=1 to print only the manual setup steps, or unset it.`,
      issues,
    ),
  };
  const lang = (env[LANG_ENV] ?? '').trim();
  if (lang !== '') {
    const code = lang.toLowerCase();
    if (languages.includes(code)) state.lang = code;
    else
      issues.push(
        invalid(
          LANG_ENV,
          `one of ${languages.join(', ')}`,
          lang,
          `Set ${LANG_ENV} to one of ${languages.join(', ')}, or unset it to choose in the wizard.`,
        ),
      );
  }
  return issues.length > 0 ? { ok: false, issues } : { ok: true, value: state };
}
