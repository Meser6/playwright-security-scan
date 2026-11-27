// The shard merge (17, chapter 6; ADR-0014): `PW_SEC_MODE=merge npx pw-sec` reads the shard files of
// reports/pw-sec/, checks the set (17-REQ-10) and finishes the run once, like the reporter of a run
// without shards (17-REQ-11). No Playwright, no browser, no request.
// Source: playwright-performance-regression src/reporter/merge.ts (MIT, same author; D-08),
// adapted to the security data and reporter.
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { join, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { combineAuthz } from '../core/authz/evaluate.ts';
import { addCoverage, emptyCoverage } from '../core/coverage.ts';
import type { ResolvedSecurityConfig } from '../core/config/index.ts';
import { defineRule } from '../core/custom/define.ts';
import { dedupeRun } from '../core/fingerprint/index.ts';
import { resolveNormalization } from '../core/normalize/index.ts';
import { asciiTerminal, colorEnabled, DEFAULT_WIDTH } from '../core/report/console.ts';
import type { TerminalOptions } from '../core/report/console.ts';
import type {
  Diagnostic,
  OutcomeFile,
  RunReport,
  ShardInfo,
  TestContextRef,
} from '../core/types/index.ts';
import { Diagnostics, finishRun } from '../reporter/finish.ts';
import type { RunData } from '../reporter/finish.ts';
import { isShardFileName, parseShardFile, stableStringify } from '../reporter/shard-file.ts';
import type { ConfigSnapshot, ShardFile } from '../reporter/shard-file.ts';

/** The merge folder, relative to the working directory (17-REQ-09). */
export const MERGE_DIR = 'reports/pw-sec';

/** Fields that must be equal in every shard file (17-REQ-10). */
const EQUAL_FIELDS = [
  'pkgVersion',
  'playwrightVersion',
  'mode',
  'total',
  'config',
  'paths',
] as const;

type EqualField = (typeof EQUAL_FIELDS)[number];

const FIELD_NAMES: Record<EqualField, string> = {
  pkgVersion: 'package version',
  playwrightVersion: 'Playwright version',
  mode: 'mode',
  total: 'number of shards',
  config: 'package config',
  paths: 'paths',
};

function fieldValue(file: ShardFile, field: EqualField): string {
  return stableStringify(field === 'total' ? file.shard.total : file[field]);
}

export interface ShardSetInput {
  /** Shard file names of the merge folder and their text; null for an unreadable file. */
  files: readonly { name: string; text: string | null }[];
  /** Whether paths.configDir with paths.configFile exists below the working directory. */
  configFound(paths: ShardFile['paths']): boolean;
}

/** Result of the validation (17-REQ-10). */
export type ShardSet =
  | { kind: 'none'; errors: Diagnostic[] }
  | { kind: 'fatal'; mode: 'scan' | 'baseline' | null; errors: Diagnostic[] }
  | {
      kind: 'ok';
      shards: ShardFile[];
      total: number;
      missing: number[];
      /** Errors that do not stop the merge (skipped files, missing shards) and warnings. */
      diagnostics: Diagnostic[];
    };

const list = (items: readonly (string | number)[]): string => items.map(String).join(', ');

const error = (code: string, message: string): Diagnostic => ({ code, level: 'error', message });

/** Checks the shard files of a merge (17-REQ-10); every row of its table is one branch here. */
export function validateShardSet(input: ShardSetInput): ShardSet {
  const named = input.files.filter((f) => isShardFileName(f.name));
  if (named.length === 0) {
    return {
      kind: 'none',
      errors: [
        error(
          'MERGE_NO_SHARD_FILES',
          `no shard files (shard-<i>-of-<n>.json) in ${MERGE_DIR}/; download the shard-*.json files of all shard jobs there and run the merge from the directory where the shards ran the test command`,
        ),
      ],
    };
  }
  const diagnostics: Diagnostic[] = [];
  const valid: { name: string; file: ShardFile }[] = [];
  for (const { name, text } of [...named].sort((a, b) => (a.name < b.name ? -1 : 1))) {
    const parsed =
      text === null
        ? { ok: false as const, reason: 'the file could not be read' }
        : parseShardFile(text);
    if (!parsed.ok) {
      diagnostics.push(
        error(
          'MERGE_SHARD_INVALID',
          `${name} was skipped: ${parsed.reason}; use the shard files written by the shard jobs of this run, unchanged`,
        ),
      );
      continue;
    }
    valid.push({ name, file: parsed.value });
  }
  if (valid.length === 0) return { kind: 'fatal', mode: null, errors: diagnostics };
  valid.sort((a, b) => a.file.shard.current - b.file.shard.current || (a.name < b.name ? -1 : 1));
  const first = valid[0] as { name: string; file: ShardFile };
  const mode = first.file.mode;

  for (const field of EQUAL_FIELDS) {
    const groups = new Map<string, string[]>();
    for (const { name, file } of valid) {
      const value = fieldValue(file, field);
      groups.set(value, [...(groups.get(value) ?? []), name]);
    }
    if (groups.size > 1) {
      const parts = [...groups.values()].map((names) => list(names));
      return {
        kind: 'fatal',
        mode,
        errors: [
          ...diagnostics,
          error(
            'MERGE_SHARD_MISMATCH',
            `the shard files differ in the ${FIELD_NAMES[field]} (${field}): ${parts.join(' vs ')}; merge the shard files of one run (same package version, mode, config and number of shards)`,
          ),
        ],
      };
    }
  }

  const byIndex = new Map<number, string[]>();
  for (const { name, file } of valid) {
    byIndex.set(file.shard.current, [...(byIndex.get(file.shard.current) ?? []), name]);
  }
  const duplicates = [...byIndex].filter(([, names]) => names.length > 1);
  if (duplicates.length > 0) {
    return {
      kind: 'fatal',
      mode,
      errors: [
        ...diagnostics,
        ...duplicates.map(([index, names]) =>
          error(
            'MERGE_SHARD_DUPLICATE',
            `shard ${String(index)} has more than one file: ${list(names)}; keep one file per shard in ${MERGE_DIR}/`,
          ),
        ),
      ],
    };
  }

  if (!input.configFound(first.file.paths)) {
    const { configDir, configFile } = first.file.paths;
    return {
      kind: 'fatal',
      mode,
      errors: [
        ...diagnostics,
        error(
          'MERGE_WRONG_DIRECTORY',
          `the Playwright config of the shards (${configDir === '.' ? '' : `${configDir}/`}${configFile}) is not below the working directory; run the merge from the directory where the shards ran the test command (in CI: the root of the checkout)`,
        ),
      ],
    };
  }

  const shards = valid.map((v) => v.file);
  const total = first.file.shard.total;
  const missing = Array.from({ length: total }, (_, i) => i + 1).filter((n) => !byIndex.has(n));
  if (missing.length > 0) {
    diagnostics.push(
      error(
        'MERGE_SHARD_MISSING',
        `${missing.length === 1 ? 'shard' : 'shards'} ${missing.map((n) => `${String(n)}/${String(total)}`).join(', ')} ${missing.length === 1 ? 'is' : 'are'} missing; the report covers the other shards only and the baseline is not written. Every shard job must upload ${MERGE_DIR}/shard-*.json, also when it failed`,
      ),
    );
  }
  const commits = new Set(shards.flatMap((s) => (s.ci.commit === null ? [] : [s.ci.commit])));
  if (commits.size > 1) {
    diagnostics.push({
      code: 'MERGE_SHARDS_DIFFERENT_COMMIT',
      level: 'warn',
      message: `the shards ran on ${String(commits.size)} different commits: ${list([...commits].map((c) => c.slice(0, 7)).sort())}; merge the shard files of one pipeline run`,
    });
  }
  return { kind: 'ok', shards, total, missing, diagnostics };
}

/** The config of the merge from the snapshot of the shard files (17, chapter 12a). */
export function configFromSnapshot(snapshot: ConfigSnapshot): ResolvedSecurityConfig {
  const { normalization: _fingerprint, customRules, ...rest } = snapshot;
  return {
    ...rest,
    normalization: resolveNormalization(undefined),
    customRules: customRules.map((meta) =>
      defineRule({
        ...meta,
        check: () => {
          throw new Error('custom rules do not run in the merge');
        },
      }),
    ),
  };
}

/** The run data of all shards (17-REQ-11): the reporter deduplicates them like one run. */
export function combineShards(shards: readonly ShardFile[]): {
  data: RunData;
  tests: Map<string, TestContextRef>;
  list: ShardInfo[];
} {
  const coverage = emptyCoverage();
  const diagnostics = new Diagnostics();
  const tests = new Map<string, TestContextRef>();
  const withoutTraffic = new Map<string, TestContextRef>();
  for (const shard of shards) {
    addCoverage(coverage, shard.coverage);
    for (const d of shard.diagnostics) diagnostics.add(d);
    for (const f of shard.findings) tests.set(f.firstSeen.testId, f.firstSeen);
    for (const t of shard.testsWithoutTraffic) {
      withoutTraffic.set(t.testId, t);
      tests.set(t.testId, t);
    }
  }
  return {
    data: {
      findings: shards.flatMap((s) => s.findings),
      coverage,
      diagnostics: diagnostics.list(),
      testsWithoutTraffic: [...withoutTraffic.values()],
      testsPassed: shards.every((s) => s.status === 'passed'),
      authz: combineAuthz(shards.map((s) => s.authz)),
      attack: null,
    },
    tests,
    list: shards.map((s) => ({
      index: s.shard.current,
      runId: s.runId,
      startedAt: s.startedAt,
      finishedAt: s.finishedAt,
      tests: s.tests.total,
      findings: dedupeRun(s.findings).length,
      responses: s.coverage.responses,
      buildUrl: s.ci.buildUrl,
    })),
  };
}

export interface MergeHost {
  cwd: string;
  env: Readonly<Record<string, string | undefined>>;
  stdout: { write(text: string): unknown; isTTY?: boolean; columns?: number };
  stderr: { write(text: string): unknown };
}

const runId = (): string =>
  `${new Date().toISOString().replace(/[-:.]/g, '').slice(0, 15)}-${randomBytes(3).toString('hex')}`;

function readFiles(dir: string): { name: string; text: string | null }[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter(isShardFileName)
    .map((name) => {
      try {
        return { name, text: readFileSync(join(dir, name), 'utf8') };
      } catch {
        return { name, text: null };
      }
    });
}

/**
 * Runs the merge in the working directory of `host` (17-REQ-09…13) and returns the exit code: the
 * code of the outcome (0/1/2/3/4), 3 when the merge cannot start.
 */
export function runMerge(host: MergeHost): number {
  const dir = resolve(host.cwd, MERGE_DIR);
  const outcomePath = join(dir, 'outcome.json');
  const out = host.stdout;
  const terminal: TerminalOptions = {
    width:
      out.isTTY === true && out.columns !== undefined && out.columns > 0
        ? out.columns
        : DEFAULT_WIDTH,
    color: colorEnabled(out, host.env),
    ascii: asciiTerminal(host.env),
  };
  const write = (line: string): void => {
    out.write(`${line}\n`);
  };
  let mode: 'scan' | 'baseline' | null = null;
  try {
    // The outcome of an earlier run must never be read by a CI job.
    rmSync(outcomePath, { force: true });
    const set = validateShardSet({
      files: readFiles(dir),
      configFound: (paths) => {
        const configDir = resolve(host.cwd, paths.configDir);
        if (!existsSync(configDir) || !statSync(configDir).isDirectory()) return false;
        return paths.configFile === '' || existsSync(join(configDir, paths.configFile));
      },
    });
    if (set.kind !== 'ok') {
      if (set.kind === 'fatal') mode = set.mode;
      return fail(set.errors);
    }
    const first = set.shards[0] as ShardFile;
    mode = first.mode;
    const combined = combineShards(set.shards);
    const shards: RunReport['shards'] = {
      total: set.total,
      missing: set.missing,
      list: combined.list,
    };
    const startedAt = set.shards.map((s) => s.startedAt).sort()[0] ?? new Date().toISOString();
    const finishedAt =
      set.shards
        .map((s) => s.finishedAt)
        .sort()
        .at(-1) ?? startedAt;
    const outcome = finishRun(
      {
        ...combined.data,
        diagnostics: [...combined.data.diagnostics, ...set.diagnostics],
      },
      {
        config: configFromSnapshot(first.config),
        mode: first.mode,
        scope: first.scope,
        runId: runId(),
        startedAt,
        finishedAt: () => finishedAt,
        playwrightVersion: first.playwrightVersion,
        configDir: resolve(host.cwd, first.paths.configDir),
        reportDir: dir,
        partial: set.shards.some((s) => s.partial) || set.missing.length > 0,
        shards,
        tests: combined.tests,
        write,
        terminal,
      },
    );
    return outcome.code;
  } catch (e) {
    return fail([
      error(
        'MERGE_INTERNAL_ERROR',
        `unexpected error in the merge: ${e instanceof Error ? (e.stack ?? e.message) : String(e)}; this is a bug in the package, please report it`,
      ),
    ]);
  }

  /** No evaluation: the errors, and outcome.json with code 3 when the mode is known. */
  function fail(errors: Diagnostic[]): number {
    for (const d of errors) host.stderr.write(`pw-sec: ${d.code}: ${d.message}\n`);
    if (mode === null) {
      write('Outcome: merge not started (code 3)');
      return 3;
    }
    const result: OutcomeFile = {
      schemaVersion: 2,
      code: 3,
      name: 'TOOL_ERROR',
      mode,
      shard: null,
      testsPassed: false,
      newBlocking: null,
      newNonBlocking: null,
      expired: null,
      resolved: null,
    };
    try {
      mkdirSync(dir, { recursive: true });
      writeFileSync(outcomePath, `${JSON.stringify(result, null, 2)}\n`);
      write(`Outcome: TOOL_ERROR (code 3), ${outcomePath}`);
    } catch (e) {
      host.stderr.write(
        `pw-sec: the outcome file could not be written to ${outcomePath}: ${e instanceof Error ? e.message : String(e)}\n`,
      );
    }
    return 3;
  }
}
