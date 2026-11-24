// Scan mode from the environment (04, chapter 2). Fixed for the life of the process.
import type { ConfigIssue } from '../core/config/index.ts';

export const MODE_ENV = 'PW_SEC_MODE';
export const CONFIG_ENV = 'PW_SEC_CONFIG';
/** Set by the main process for the workers: one run id and one redaction salt per run (07-REQ-15). */
export const RUN_ID_ENV = 'PW_SEC_RUN_ID';
export const SALT_ENV = 'PW_SEC_RUN_SALT';

export type ScanMode = 'scan' | 'baseline';
const MODES = ['scan', 'baseline'] as const;

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
  if (value === 'active') {
    return {
      ok: false,
      issues: [
        {
          code: 'MODE_NOT_AVAILABLE',
          path: MODE_ENV,
          message: `${MODE_ENV}=active: the active scan is not available in this version; the package is passive only`,
          hint: `Use ${MODE_ENV}=scan or ${MODE_ENV}=baseline.`,
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

/** Whether the scan is on, for the fixtures; invalid values were rejected by withSecurity(). */
export function scanModeOn(
  env: Readonly<Record<string, string | undefined>> = process.env,
): boolean {
  const mode = readMode(env);
  return mode.ok && mode.mode !== null;
}
