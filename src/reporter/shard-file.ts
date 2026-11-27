// Shard files (17, chapter 5): a scan or baseline run with --shard=i/n does not classify; it writes
// the findings per test, the coverage and what the merge needs to finish the run to
// <report.dir>/shard-<i>-of-<n>.json. An internal format: written and read by the same package
// version, no schema file and no migration (17-REQ-07).
// Source: playwright-performance-regression src/reporter/shard-file.ts (MIT, same author; D-08),
// adapted to the security data.
import { createHash } from 'node:crypto';
import type { AuthzRunData } from '../core/authz/types.ts';
import type { ResolvedSecurityConfig } from '../core/config/index.ts';
import type { Rule as CustomRule, RuleDefinition } from '../core/custom/define.ts';
import type { Coverage, Diagnostic, Finding, TestContextRef } from '../core/types/index.ts';

export const SHARD_FILE_FORMAT = 'pw-sec-shard';
export const SHARD_FILE_VERSION = 1;

export interface ShardNumber {
  current: number;
  total: number;
}

/** File name of shard i of n in report.dir (17-REQ-07). */
export function shardFileName(shard: ShardNumber): string {
  return `shard-${String(shard.current)}-of-${String(shard.total)}.json`;
}

/** shard-<i>-of-<n>.json names, for the merge (17-REQ-09). */
export function isShardFileName(name: string): boolean {
  return /^shard-[1-9][0-9]*-of-[1-9][0-9]*\.json$/u.test(name);
}

/** Metadata of a custom rule without `check` (16-REQ-13). */
export type CustomRuleMeta = Omit<RuleDefinition, 'check'>;

/** The validated config without functions (17-REQ-07, 16-REQ-13). */
export type ConfigSnapshot = Omit<ResolvedSecurityConfig, 'normalization' | 'customRules'> & {
  /** Fingerprint of the normalization config, with functions as their source text. */
  normalization: string;
  customRules: CustomRuleMeta[];
};

export interface CiInfo {
  commit: string | null;
  branch: string | null;
  buildUrl: string | null;
}

export interface ShardFile {
  format: typeof SHARD_FILE_FORMAT;
  schemaVersion: typeof SHARD_FILE_VERSION;
  pkgVersion: string;
  playwrightVersion: string;
  shard: ShardNumber;
  runId: string;
  startedAt: string;
  finishedAt: string;
  mode: 'scan' | 'baseline';
  /** The arguments filtered the tests other than with --shard (17-REQ-06). */
  partial: boolean;
  /** Relative to the working directory of the Playwright process, with "/" (17-REQ-07). */
  paths: { configDir: string; configFile: string; baselinePath: string };
  config: ConfigSnapshot;
  /** Scope origins of the run, as in report.scope.origins. */
  scope: string[];
  ci: CiInfo;
  /** FullResult.status of the shard. */
  status: string;
  tests: { total: number; passed: number; failed: number; flaky: number; skipped: number };
  /** Per test, deduplicated within the test (17-D-02). */
  findings: Finding[];
  coverage: Coverage;
  /** Every test without traffic in scope (no limit). */
  testsWithoutTraffic: TestContextRef[];
  diagnostics: Diagnostic[];
  /** Raw replay results of the authorization tests (18-REQ-20); null when they are off. */
  authz: AuthzRunData | null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

const REQUIRED: readonly (keyof ShardFile)[] = [
  'pkgVersion',
  'playwrightVersion',
  'shard',
  'runId',
  'startedAt',
  'finishedAt',
  'mode',
  'partial',
  'paths',
  'config',
  'scope',
  'ci',
  'status',
  'tests',
  'findings',
  'coverage',
  'testsWithoutTraffic',
  'diagnostics',
  'authz',
];

/**
 * A shard file, or the reason it is not accepted (17-REQ-10, MERGE_SHARD_INVALID): no valid JSON,
 * another format or version, or missing fields.
 */
export function parseShardFile(
  text: string,
): { ok: true; value: ShardFile } | { ok: false; reason: string } {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return { ok: false, reason: 'the file is not valid JSON' };
  }
  if (!isRecord(value) || value.format !== SHARD_FILE_FORMAT) {
    return { ok: false, reason: 'the file is no shard file' };
  }
  if (value.schemaVersion !== SHARD_FILE_VERSION) {
    return {
      ok: false,
      reason: `the file has version ${JSON.stringify(value.schemaVersion)} of the shard format, expected ${String(SHARD_FILE_VERSION)}`,
    };
  }
  const missing = REQUIRED.filter((name) => !Object.hasOwn(value, name));
  if (missing.length > 0) {
    return { ok: false, reason: `fields are missing: ${missing.join(', ')}` };
  }
  const shard = value.shard;
  if (
    !isRecord(shard) ||
    !Number.isInteger(shard.current) ||
    !Number.isInteger(shard.total) ||
    (shard.current as number) < 1 ||
    (shard.current as number) > (shard.total as number)
  ) {
    return { ok: false, reason: 'the shard number is not valid' };
  }
  if (
    (value.mode !== 'scan' && value.mode !== 'baseline') ||
    !Array.isArray(value.findings) ||
    !Array.isArray(value.diagnostics) ||
    !Array.isArray(value.testsWithoutTraffic) ||
    !Array.isArray(value.scope) ||
    !isRecord(value.coverage) ||
    !isRecord(value.config) ||
    !isRecord(value.paths) ||
    !isRecord(value.tests) ||
    !isRecord(value.ci)
  ) {
    return { ok: false, reason: 'the file is incomplete' };
  }
  return { ok: true, value: value as unknown as ShardFile };
}

/** JSON with sorted keys; RegExp and functions as text (stable across processes). */
export function stableStringify(value: unknown): string {
  return JSON.stringify(value, (_key, v: unknown) => {
    if (v instanceof RegExp) return `/${v.source}/${v.flags}`;
    if (typeof v === 'function') return `function:${String(v)}`;
    if (isRecord(v)) {
      return Object.fromEntries(
        Object.keys(v)
          .sort()
          .map((k) => [k, v[k]]),
      );
    }
    return v;
  });
}

/** Metadata of a custom rule (16-REQ-13): everything of the definition except `check`. */
export function customRuleMeta(rule: CustomRule): CustomRuleMeta {
  const { check: _check, ...meta } = rule;
  return JSON.parse(JSON.stringify(meta)) as CustomRuleMeta;
}

/** The config snapshot of a shard file (17-REQ-07). */
export function configSnapshot(config: ResolvedSecurityConfig): ConfigSnapshot {
  const { normalization, customRules, ...rest } = config;
  const plain = JSON.parse(JSON.stringify(rest)) as Omit<
    ResolvedSecurityConfig,
    'normalization' | 'customRules'
  >;
  // Credential headers of the roles never reach a file (18-AC-07, 18 chapter 12a).
  for (const role of Object.values(plain.authz.roles)) {
    if (role.headers !== undefined) {
      role.headers = Object.fromEntries(Object.keys(role.headers).map((k) => [k, '[redacted]']));
    }
  }
  return {
    ...plain,
    normalization: createHash('sha256').update(stableStringify(normalization)).digest('hex'),
    customRules: customRules.map(customRuleMeta),
  };
}
