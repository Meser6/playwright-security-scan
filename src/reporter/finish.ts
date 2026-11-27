// The end of a run (04, 08, 09): deduplication of the run, classification against the baseline,
// the baseline write, reports, outcome.json and the summary. The reporter of a run without shards
// and the shard merge (17-REQ-11) both finish here, so a merged run gives the same result.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import {
  classify,
  missingNotes,
  outcome as computeOutcome,
  parseBaseline,
  resolveEntries,
  serializeBaseline,
  updateBaseline,
} from '../core/baseline/index.ts';
import type { BaselineDiff } from '../core/baseline/index.ts';
import type { ResolvedSecurityConfig } from '../core/config/index.ts';
import { sortCoverage } from '../core/coverage.ts';
import { compareTests, dedupeRun } from '../core/fingerprint/index.ts';
import { RULE_IDS } from '../core/manifest/rules.ts';
import { formatBaselineDiff, formatSummary } from '../core/report/console.ts';
import type { TerminalOptions } from '../core/report/console.ts';
import type {
  BaselineFile,
  Coverage,
  Diagnostic,
  Finding,
  OutcomeFile,
  RunReport,
  TestContextRef,
} from '../core/types/index.ts';
import { VERSION } from '../version.ts';
import { REPORT_WRITERS } from './sarif-junit.ts';

export const MAX_TESTS_WITHOUT_TRAFFIC = 50;

export const today = (): string => new Date().toISOString().slice(0, 10);

/** What the tests of a run produced (summed over the shards in a merge). */
export interface RunData {
  /** Findings per test, as in the attachments (07-REQ-09); deduplicated here (07-REQ-10). */
  findings: readonly Finding[];
  coverage: Coverage;
  diagnostics: readonly Diagnostic[];
  /** Every test without traffic in scope; sorted and cut to 50 here. */
  testsWithoutTraffic: readonly TestContextRef[];
  testsPassed: boolean;
}

export interface FinishOptions {
  config: ResolvedSecurityConfig;
  mode: 'scan' | 'baseline';
  /** Scope origins of the run, sorted. */
  scope: string[];
  runId: string;
  startedAt: string;
  finishedAt: () => string;
  playwrightVersion: string;
  /** Absolute directory of the Playwright config: relative option paths start there. */
  configDir: string;
  /** Absolute directory of report.json, the HTML report, SARIF and outcome.json. */
  reportDir: string;
  /** Some test was filtered out (04-REQ-03): resolved baseline entries are kept. */
  partial: boolean;
  shards: RunReport['shards'];
  /** Tests of the run by id, for the test list of the HTML report (09, chapter 3.7). */
  tests: ReadonlyMap<string, TestContextRef>;
  write: (line: string) => void;
  terminal: TerminalOptions;
}

/** Collects diagnostics once per code and message. */
export class Diagnostics {
  readonly #map = new Map<string, Diagnostic>();

  add(d: Diagnostic): void {
    const key = `${d.code}\u0000${d.message}`;
    if (!this.#map.has(key)) this.#map.set(key, d);
  }

  list(): Diagnostic[] {
    return [...this.#map.values()];
  }
}

function toolError(where: string, error: unknown): Diagnostic {
  return {
    code: 'REPORTER_ERROR',
    level: 'error',
    message: `reporter: ${where} failed: ${error instanceof Error ? error.message : String(error)}`,
  };
}

/** Finishes a scan or baseline run and returns its outcome (00, chapter 11). */
export function finishRun(data: RunData, options: FinishOptions): OutcomeFile {
  const { config: sec, mode, scope } = options;
  const diags = new Diagnostics();
  for (const d of data.diagnostics) diags.add(d);
  const path = (p: string): string => (isAbsolute(p) ? p : resolve(options.configDir, p));
  const enabled = new Set(
    Object.entries(sec.rules)
      .filter(([, r]) => r.enabled)
      .map(([id]) => id),
  );
  const findings = dedupeRun(data.findings);
  const coverage = sortCoverage(data.coverage);
  const date = today();

  // Baseline file (08): only baseline.path (D-17).
  const baselineName = sec.baseline.path;
  const baselinePath = path(baselineName);
  let baseline: BaselineFile | undefined;
  let baselineOk = true;
  if (existsSync(baselinePath)) {
    const parsed = parseBaseline(
      readFileSync(baselinePath, 'utf8'),
      baselineName,
      new Set(RULE_IDS),
      enabled,
    );
    for (const d of parsed.diagnostics) diags.add(d);
    if (parsed.ok) baseline = parsed.file;
    else baselineOk = false;
  }
  if (mode === 'scan' && sec.baseline.requireNote) {
    for (const d of missingNotes(baseline)) diags.add(d);
  }

  const gate = sec.gate;
  const classified = classify(findings, baseline, gate, date, mode === 'scan');
  const { resolved, notCovered } = resolveEntries(baseline, findings, coverage, enabled);

  if (coverage.responses === 0) {
    diags.add({
      code: 'NO_TRAFFIC',
      level: gate.failOnNoTraffic ? 'warn' : 'info',
      message:
        scope.length === 0
          ? 'no response was in scope: set `use.baseURL` or `scope.origins`'
          : `no response was in scope (${scope.join(', ')}); check scope.origins and that the tests use the fixtures of withSecurityFixtures()`,
    });
  }

  // Baseline run: write the file (08-REQ-08), unless the existing one is invalid.
  let diff: BaselineDiff | undefined;
  const partial = options.partial;
  if (mode === 'baseline' && partial) {
    diags.add({
      code: 'PARTIAL_RUN',
      level: 'warn',
      message:
        options.shards === null
          ? 'baseline: the run is filtered (grep, project, files or only-changed), so resolved entries are kept (04-REQ-03)'
          : 'baseline: a shard was filtered (grep, project, files or only-changed) or is missing, so resolved entries are kept (17-REQ-11)',
    });
  }
  // A merge with missing shards writes no baseline at all (17-REQ-10).
  const missingShards = (options.shards?.missing.length ?? 0) > 0;
  if (mode === 'baseline' && baselineOk && !missingShards) {
    const update = updateBaseline(baseline, findings, resolved, {
      today: date,
      generatedBy: `playwright-security-scan@${VERSION}`,
      prune: sec.baseline.pruneResolved && !partial,
    });
    try {
      mkdirSync(dirname(baselinePath), { recursive: true });
      writeFileSync(baselinePath, serializeBaseline(update.file));
      diff = update.diff;
    } catch (error) {
      diags.add(toolError(`writing ${baselineName}`, error));
    }
  }

  const diagnostics = diags.list();
  const out = computeOutcome({
    findings: classified,
    resolved: resolved.length,
    diagnostics,
    testsPassed: data.testsPassed,
    responses: coverage.responses,
    gate,
    mode,
  });
  const report: RunReport = {
    schemaVersion: 2,
    runId: options.runId,
    startedAt: options.startedAt,
    finishedAt: options.finishedAt(),
    mode,
    shards: options.shards,
    pkgVersion: VERSION,
    playwrightVersion: options.playwrightVersion,
    scope: { origins: scope },
    coverage,
    findings: [...classified].sort((a, b) => (a.fingerprint < b.fingerprint ? -1 : 1)),
    resolved,
    notCovered,
    testsWithoutTraffic: [...data.testsWithoutTraffic]
      .sort(compareTests)
      .slice(0, MAX_TESTS_WITHOUT_TRAFFIC),
    gate: {
      minSeverity: gate.minSeverity,
      minConfidence: gate.minConfidence,
      failed: out.code === 1 || out.code === 2,
      blocking: classified.filter((f) => f.blocking).map((f) => f.fingerprint),
    },
    diagnostics,
    outcome: out,
  };

  // Reports are written also when tests failed or the tool failed (09-REQ-02).
  const dir = options.reportDir;
  const written: { html: string | null; json: string | null } = { html: null, json: null };
  try {
    mkdirSync(dir, { recursive: true });
    if (sec.report.json) {
      writeFileSync(join(dir, 'report.json'), `${JSON.stringify(report, null, 2)}\n`);
      written.json = join(dir, 'report.json');
    }
    writeFileSync(join(dir, 'outcome.json'), `${JSON.stringify(out, null, 2)}\n`);
    for (const writer of REPORT_WRITERS) {
      const file = writer.write(report, sec, {
        reportDir: dir,
        configDir: options.configDir,
        tests: options.tests,
      });
      if (writer.name === 'html' && file !== null) written.html = resolve(file);
    }
  } catch (error) {
    options.write(
      `pw-sec: could not write the reports: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  if (diff !== undefined) {
    for (const line of formatBaselineDiff(baselineName, diff, partial, options.terminal))
      options.write(line);
  }
  // Absolute path: terminals show it as a link whatever the current directory (04-REQ-07).
  const reportPath = written.html ?? written.json;
  for (const line of formatSummary(report, reportPath, options.terminal)) options.write(line);
  return out;
}
