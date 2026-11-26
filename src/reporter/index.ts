// The package reporter (01-REQ-07; 04; 08; 09): collects the test attachments, deduplicates the
// findings of the run, compares them with the baseline, writes the reports and the baseline, and
// prints the start banner and the summary. Never throws: a failure becomes TOOL_ERROR (P-08).
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import type {
  FullConfig,
  FullResult,
  Reporter,
  Suite,
  TestCase,
  TestResult,
} from '@playwright/test/reporter';
import {
  baselineFileFor,
  classify,
  missingNotes,
  outcome as computeOutcome,
  parseBaseline,
  resolveEntries,
  serializeBaseline,
  updateBaseline,
} from '../core/baseline/index.ts';
import type { BaselineDiff } from '../core/baseline/index.ts';
import { enabledRuleCount, resolveConfig } from '../core/config/index.ts';
import type { ResolvedSecurityConfig } from '../core/config/index.ts';
import { addCoverage, emptyCoverage, sortCoverage } from '../core/coverage.ts';
import { compareTests, dedupeRun } from '../core/fingerprint/index.ts';
import { RULE_IDS } from '../core/manifest/rules.ts';
import {
  asciiTerminal,
  colorEnabled,
  DEFAULT_WIDTH,
  formatBaselineDiff,
  formatBanner,
  formatSummary,
} from '../core/report/console.ts';
import type { TerminalOptions } from '../core/report/console.ts';
import type {
  BaselineFile,
  Diagnostic,
  Finding,
  RunReport,
  TestAttachment,
  TestContextRef,
} from '../core/types/index.ts';
import { ATTACHMENT_NAME } from '../collector/test-collector.ts';
import { readMode, RUN_ID_ENV } from '../mode/index.ts';
import { getRegistered } from '../registry/index.ts';
import { VERSION } from '../version.ts';
import { isPartialRun } from './partial.ts';
import { REPORT_WRITERS } from './sarif-junit.ts';

const MAX_TESTS_WITHOUT_TRAFFIC = 50;

const today = (): string => new Date().toISOString().slice(0, 10);

export interface ReporterOptions {
  /** Where the console output goes; tests pass a collector. */
  write?: (line: string) => void;
  /** The output stream for the color and width decision (04-REQ-05); process.stdout. */
  stdout?: { isTTY?: boolean | undefined; columns?: number | undefined };
  /** Environment for NO_COLOR, FORCE_COLOR and TERM; process.env. */
  env?: Readonly<Record<string, string | undefined>>;
}

export default class SecurityReporter implements Reporter {
  readonly #write: (line: string) => void;
  readonly #terminal: TerminalOptions;
  #config: FullConfig | undefined;
  #suite: Suite | undefined;
  #startedAt = new Date();
  readonly #findings: Finding[] = [];
  readonly #coverage = emptyCoverage();
  readonly #diagnostics = new Map<string, Diagnostic>();
  readonly #withoutTraffic = new Map<string, TestContextRef>();
  readonly #withTraffic = new Set<string>();

  constructor(options: ReporterOptions = {}) {
    this.#write = options.write ?? ((line) => process.stdout.write(`${line}\n`));
    const out = options.stdout ?? process.stdout;
    const env = options.env ?? process.env;
    this.#terminal = {
      width:
        out.isTTY === true && out.columns !== undefined && out.columns > 0
          ? out.columns
          : DEFAULT_WIDTH,
      color: colorEnabled(out, env),
      ascii: asciiTerminal(env),
    };
  }

  printsToStdio(): boolean {
    return false;
  }

  #diag(d: Diagnostic): void {
    const key = `${d.code}\u0000${d.message}`;
    if (!this.#diagnostics.has(key)) this.#diagnostics.set(key, d);
  }

  #toolError(where: string, error: unknown): void {
    this.#diag({
      code: 'REPORTER_ERROR',
      level: 'error',
      message: `reporter: ${where} failed: ${error instanceof Error ? error.message : String(error)}`,
    });
  }

  #settings(): { config: ResolvedSecurityConfig; mode: 'scan' | 'baseline'; scope: string[] } {
    const state = getRegistered();
    if (state !== undefined) {
      const scope = [
        ...(state.config.scope.includeBaseURL ? state.baseOrigins : []),
        ...state.config.scope.origins,
      ];
      return { config: state.config, mode: state.mode, scope: [...new Set(scope)].sort() };
    }
    const fallback = resolveConfig(undefined);
    if (!fallback.ok) throw new Error('the default config is invalid');
    const mode = readMode(process.env);
    return {
      config: fallback.config,
      mode: mode.ok && mode.mode !== null ? mode.mode : 'scan',
      scope: [],
    };
  }

  #configDir(): string {
    const config = this.#config;
    if (config?.configFile !== undefined) return dirname(config.configFile);
    return config?.rootDir ?? process.cwd();
  }

  #path(path: string): string {
    return isAbsolute(path) ? path : resolve(this.#configDir(), path);
  }

  onBegin(config: FullConfig, suite: Suite): void {
    this.#config = config;
    this.#suite = suite;
    this.#startedAt = new Date();
    try {
      const { config: sec, mode, scope } = this.#settings();
      const notes: Diagnostic[] = [];
      const state = getRegistered();
      if (state === undefined) {
        this.#diag({
          code: 'CONFIG_MISSING',
          level: 'error',
          message:
            'config: the reporter runs but withSecurity() was not applied to the Playwright config; wrap it with withSecurity() from "playwright-security-scan/config"',
        });
      } else {
        for (const w of state.warnings) {
          this.#diag(w);
          if (w.code !== 'SCOPE_EMPTY') notes.push(w);
        }
      }
      if ((process.env.PW_PERF_MODE ?? '') !== '') {
        const w: Diagnostic = {
          code: 'PERF_MODE_ACTIVE',
          level: 'warn',
          message:
            'PW_PERF_MODE is set too: analysing response bodies adds load to the workers and may distort step timings; run the two scans in separate CI jobs',
        };
        this.#diag(w);
        notes.push(w);
      }
      let entries: number | null = null;
      const baselineName = baselineFileFor(sec.baseline.path, sec.run.env);
      const file = this.#path(baselineName);
      if (existsSync(file)) {
        try {
          const parsed = JSON.parse(readFileSync(file, 'utf8')) as { findings?: object };
          entries = Object.keys(parsed.findings ?? {}).length;
        } catch {
          entries = 0;
        }
      }
      const reportFile = sec.report.html ? 'report.html' : 'report.json';
      const banner = formatBanner(
        {
          mode,
          env: sec.run.env,
          scope,
          enabledRules: enabledRuleCount(sec),
          preset: sec.preset,
          minSeverity: sec.gate.minSeverity,
          minConfidence: sec.gate.minConfidence,
          baselinePath: baselineName,
          baselineEntries: entries,
          reportPath: `${sec.report.dir.replace(/[\\/]+$/, '')}/${reportFile}`,
          notes,
        },
        this.#terminal,
      );
      for (const line of banner) this.#write(line);
    } catch (error) {
      this.#toolError('the start of the run', error);
    }
  }

  #ref(test: TestCase): TestContextRef {
    const root = this.#configDir();
    // titlePath(): root, project, file, describes…, title.
    return {
      testId: test.id,
      titlePath: test.titlePath().slice(3),
      file: relative(root, test.location.file).split('\\').join('/'),
      line: test.location.line,
      project: test.parent.project()?.name ?? '',
    };
  }

  onTestEnd(test: TestCase, result: TestResult): void {
    try {
      for (const a of result.attachments) {
        if (a.name !== ATTACHMENT_NAME) continue;
        const text =
          a.body !== undefined
            ? a.body.toString('utf8')
            : a.path !== undefined
              ? readFileSync(a.path, 'utf8')
              : '';
        let doc: TestAttachment;
        try {
          doc = JSON.parse(text) as TestAttachment;
        } catch {
          this.#diag({
            code: 'ATTACHMENT_INVALID',
            level: 'warn',
            message: `the findings attachment of "${test.title}" could not be read`,
            testId: test.id,
          });
          continue;
        }
        // Every attempt counts, also one that a retry later passed (01-REQ-07).
        this.#findings.push(...doc.findings);
        addCoverage(this.#coverage, doc.coverage);
        for (const d of doc.diagnostics) this.#diag(d);
        if (doc.coverage.responses > 0) {
          this.#withTraffic.add(test.id);
          this.#withoutTraffic.delete(test.id);
        } else if (!this.#withTraffic.has(test.id)) {
          this.#withoutTraffic.set(test.id, this.#ref(test));
        }
      }
    } catch (error) {
      this.#toolError(`reading the results of "${test.title}"`, error);
    }
  }

  onEnd(result: FullResult): Promise<{ status?: FullResult['status'] } | undefined> {
    try {
      return Promise.resolve(this.#finish(result));
    } catch (error) {
      this.#write(
        `pw-sec: internal error: ${error instanceof Error ? error.message : String(error)}`,
      );
      return Promise.resolve({ status: 'failed' });
    }
  }

  #finish(result: FullResult): { status?: FullResult['status'] } | undefined {
    const { config: sec, mode, scope } = this.#settings();
    const enabled = new Set(
      Object.entries(sec.rules)
        .filter(([, r]) => r.enabled)
        .map(([id]) => id),
    );
    const findings = dedupeRun(this.#findings);
    const coverage = sortCoverage(this.#coverage);
    const date = today();

    // Baseline file (08), per environment label (08-REQ-14).
    const env = sec.run.env;
    const baselineName = baselineFileFor(sec.baseline.path, env);
    const baselinePath = this.#path(baselineName);
    let baseline: BaselineFile | undefined;
    let baselineOk = true;
    if (existsSync(baselinePath)) {
      const parsed = parseBaseline(
        readFileSync(baselinePath, 'utf8'),
        baselineName,
        new Set(RULE_IDS),
        enabled,
      );
      for (const d of parsed.diagnostics) this.#diag(d);
      if (parsed.ok) baseline = parsed.file;
      else baselineOk = false;
      if (parsed.ok && parsed.file.env !== undefined && parsed.file.env !== env) {
        this.#diag({
          code: 'BASELINE_ENV_MISMATCH',
          level: 'warn',
          message: `${baselineName} was written for the environment "${parsed.file.env}", but this run ${env === null ? 'has no environment label' : `is "${env}"`}; check PW_SEC_ENV and run.env`,
        });
      }
    } else if (env !== null && existsSync(this.#path(sec.baseline.path))) {
      this.#diag({
        code: 'BASELINE_ENV_MISSING',
        level: 'warn',
        message: `${baselineName} does not exist, so ${sec.baseline.path} (without a label) is not used for "${env}"; run PW_SEC_MODE=baseline with PW_SEC_ENV=${env}, or copy the file`,
      });
    }
    if (mode === 'scan' && sec.baseline.requireNote) {
      for (const d of missingNotes(baseline)) this.#diag(d);
    }

    const gate = sec.gate;
    const classified = classify(findings, baseline, gate, date, mode === 'scan');
    const { resolved, notCovered } = resolveEntries(baseline, findings, coverage, enabled);

    if (coverage.responses === 0) {
      this.#diag({
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
    const partial = isPartialRun(this.#config, this.#suite, process.argv);
    if (mode === 'baseline' && partial) {
      this.#diag({
        code: 'PARTIAL_RUN',
        level: 'warn',
        message:
          'baseline: the run is filtered (grep, shard, project, files or only-changed), so resolved entries are kept (04-REQ-03)',
      });
    }
    if (mode === 'baseline' && baselineOk) {
      const update = updateBaseline(baseline, findings, resolved, {
        today: date,
        generatedBy: `playwright-security-scan@${VERSION}`,
        prune: sec.baseline.pruneResolved && !partial,
        env,
      });
      try {
        mkdirSync(dirname(baselinePath), { recursive: true });
        writeFileSync(baselinePath, serializeBaseline(update.file));
        diff = update.diff;
      } catch (error) {
        this.#toolError(`writing ${baselineName}`, error);
      }
    }

    const diagnostics = [...this.#diagnostics.values()];
    const out = computeOutcome({
      findings: classified,
      resolved: resolved.length,
      diagnostics,
      testsPassed: result.status === 'passed',
      responses: coverage.responses,
      gate,
      env,
    });
    const report: RunReport = {
      schemaVersion: 1,
      runId: process.env[RUN_ID_ENV] ?? getRegistered()?.runId ?? '',
      startedAt: this.#startedAt.toISOString(),
      finishedAt: new Date().toISOString(),
      mode,
      env,
      pkgVersion: VERSION,
      playwrightVersion: this.#config?.version ?? '',
      scope: { origins: scope },
      coverage,
      findings: [...classified].sort((a, b) => (a.fingerprint < b.fingerprint ? -1 : 1)),
      resolved,
      notCovered,
      testsWithoutTraffic: [...this.#withoutTraffic.values()]
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
    const dir = this.#path(sec.report.dir);
    const written: { html: string | null; json: string | null } = { html: null, json: null };
    try {
      mkdirSync(dir, { recursive: true });
      if (sec.report.json) {
        writeFileSync(join(dir, 'report.json'), `${JSON.stringify(report, null, 2)}\n`);
        written.json = join(dir, 'report.json');
      }
      writeFileSync(join(dir, 'outcome.json'), `${JSON.stringify(out, null, 2)}\n`);
      for (const writer of REPORT_WRITERS) {
        const path = writer.write(report, sec, { reportDir: dir, configDir: this.#configDir() });
        if (writer.name === 'html' && path !== null) written.html = resolve(path);
      }
    } catch (error) {
      this.#write(
        `pw-sec: could not write the reports: ${error instanceof Error ? error.message : String(error)}`,
      );
    }

    if (diff !== undefined) {
      for (const line of formatBaselineDiff(baselineName, diff, partial, this.#terminal))
        this.#write(line);
    }
    // Absolute path: terminals show it as a link whatever the current directory (04-REQ-07).
    const reportPath = written.html ?? written.json;
    for (const line of formatSummary(report, reportPath, this.#terminal)) this.#write(line);
    return out.code === 0 ? undefined : { status: 'failed' };
  }
}
