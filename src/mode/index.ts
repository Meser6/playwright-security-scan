// Scan mode from the environment (04, chapter 2). Fixed for the life of the process.
import type { ConfigIssue } from '../core/config/index.ts';

export const MODE_ENV = 'PW_SEC_MODE';
export const CONFIG_ENV = 'PW_SEC_CONFIG';
/** The removed environment label (D-17): set, it only gives the ENV_REMOVED warning. */
export const REMOVED_ENV_ENV = 'PW_SEC_ENV';
/** Set by the main process for the workers: one run id and one redaction salt per run (07-REQ-15). */
export const RUN_ID_ENV = 'PW_SEC_RUN_ID';
export const SALT_ENV = 'PW_SEC_RUN_SALT';

export type ScanMode = 'scan' | 'baseline' | 'check';
const MODES = ['scan', 'baseline', 'check'] as const;
/** Tests of a check (04-REQ-10). */
export const MAX_TESTS_ENV = 'PW_SEC_MAX_TESTS';
export const DEFAULT_MAX_TESTS = 10;

export type ModeResult = { ok: true; mode: ScanMode | null } | { ok: false; issues: ConfigIssue[] };

/**
 * The mode from PW_SEC_MODE (04-REQ-01): unset or empty → null (the package does nothing, P-02);
 * values are case-insensitive; `active` is reserved (04-AC-01); anything else lists the values.
 */
export function readMode(env: Readonly<Record<string, string | undefined>>): ModeResult {
  const raw = (env[MODE_ENV] ?? '').trim();
  if (raw === '') return { ok: true, mode: null };
  const value = raw.toLowerCase();
  if ((MODES as readonly string[]).includes(value)) return { ok: true, mode: value as ScanMode };
  if (value === 'merge') {
    return {
      ok: false,
      issues: [
        {
          code: 'MODE_INVALID',
          path: MODE_ENV,
          message: `${MODE_ENV}=merge is not a mode of the test command: merge runs without tests`,
          hint: `Run the merge of the shard files with: ${MODE_ENV}=merge npx pw-sec (17-REQ-09).`,
        },
      ],
    };
  }
  if (value === 'active') {
    return {
      ok: false,
      issues: [
        {
          code: 'MODE_NOT_AVAILABLE',
          path: MODE_ENV,
          message: `${MODE_ENV}=active is not a mode: authorization tests are enabled in the config: authz.enabled`,
          hint: `Set authz: { enabled: true, allowedOrigins: [...] } in pw-sec.config and run ${MODE_ENV}=scan or ${MODE_ENV}=baseline (docs/authz.md).`,
        },
      ],
    };
  }
  return {
    ok: false,
    issues: [
      {
        code: 'MODE_INVALID',
        path: MODE_ENV,
        message: `${MODE_ENV}=${JSON.stringify(raw)} is not a mode`,
        hint: `Allowed values: ${MODES.join(', ')} (or unset to disable the scan).`,
      },
    ],
  };
}

/** PW_SEC_MODE=merge: the binary merges the shard files instead of the wizard (17-REQ-09). */
export function isMergeMode(env: Readonly<Record<string, string | undefined>>): boolean {
  return (env[MODE_ENV] ?? '').trim().toLowerCase() === 'merge';
}

/** Whether the scan is on, for the fixtures; invalid values were rejected by withSecurity(). */
export function scanModeOn(
  env: Readonly<Record<string, string | undefined>> = process.env,
): boolean {
  const mode = readMode(env);
  return mode.ok && mode.mode !== null;
}

export type MaxTestsResult = { ok: true; maxTests: number } | { ok: false; issues: ConfigIssue[] };

/** PW_SEC_MAX_TESTS for a check (04-REQ-10): 1 to 1000, default 10; anything else is an error. */
export function readMaxTests(env: Readonly<Record<string, string | undefined>>): MaxTestsResult {
  const raw = (env[MAX_TESTS_ENV] ?? '').trim();
  if (raw === '') return { ok: true, maxTests: DEFAULT_MAX_TESTS };
  const value = Number(raw);
  if (/^\d+$/.test(raw) && value >= 1 && value <= 1000) return { ok: true, maxTests: value };
  return {
    ok: false,
    issues: [
      {
        code: 'MAX_TESTS_INVALID',
        path: MAX_TESTS_ENV,
        message: `${MAX_TESTS_ENV}=${JSON.stringify(raw)} is not a number of tests`,
        hint: `Use a whole number from 1 to 1000 (default ${DEFAULT_MAX_TESTS}).`,
      },
    ],
  };
}

/** The check skips a test with this reason (04-REQ-10). */
export const CHECK_SKIP_REASON = 'pw-sec check: only the first test of each file runs';

/** Switches the authorization tests off for one run (18-REQ-05). */
export const AUTHZ_ENV = 'PW_SEC_AUTHZ';

export type AuthzEnvResult = { ok: true; off: boolean } | { ok: false; issues: ConfigIssue[] };

/** PW_SEC_AUTHZ (18-REQ-05): `0` switches the tests off, empty or unset changes nothing. */
export function readAuthzEnv(env: Readonly<Record<string, string | undefined>>): AuthzEnvResult {
  const raw = (env[AUTHZ_ENV] ?? '').trim();
  if (raw === '') return { ok: true, off: false };
  if (raw === '0') return { ok: true, off: true };
  return {
    ok: false,
    issues: [
      {
        code: 'AUTHZ_ENV_INVALID',
        path: AUTHZ_ENV,
        message: `${AUTHZ_ENV}=${JSON.stringify(raw)} is not a valid value`,
        hint: `Use ${AUTHZ_ENV}=0 to switch the authorization tests off for one run; they are switched on only with authz.enabled in the config.`,
      },
    ],
  };
}

/** Whether the authorization tests run: authz.enabled and not PW_SEC_AUTHZ=0 (18-REQ-05). */
export function authzOn(
  enabled: boolean,
  env: Readonly<Record<string, string | undefined>> = process.env,
): boolean {
  const r = readAuthzEnv(env);
  return enabled && r.ok && !r.off;
}
