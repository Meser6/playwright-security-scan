// The package reporter (01-REQ-07; 04; 08; 09): collects the test attachments, deduplicates the
// findings of the run, compares them with the baseline, writes the reports and the baseline, and
// prints the start banner and the summary. Never throws: a failure becomes TOOL_ERROR (P-08).
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { basename, dirname, isAbsolute, join, relative, resolve } from 'node:path';
import type {
  FullConfig,
  FullResult,
  Reporter,
  Suite,
  TestCase,
  TestResult,
} from '@playwright/test/reporter';
import {
  authzBannerText,
  authzCheckText,
  decidedResult,
  planReplays,
  resultOf,
  rolesOf,
} from '../core/authz/plan.ts';
import type { Plan, ProjectInfo, Role } from '../core/authz/plan.ts';
import { TEMPLATES_ATTACHMENT } from '../core/authz/types.ts';
import type { AuthzRunData, RequestTemplate, TemplatesAttachment } from '../core/authz/types.ts';
import { authzHash } from '../collector/templates.ts';
import { classify, parseBaseline } from '../core/baseline/index.ts';
import type { AttackRole } from '../active/zap.ts';
import {
  attackBannerText,
  attackRole,
  emptyAttackSummary,
  MUTATING_METHODS,
} from '../core/attack/config.ts';
import type { AttackRunData, AttackTemplate } from '../core/attack/types.ts';
import { Redactor } from '../core/fingerprint/index.ts';
import { canonicalOrigin, createKeyBuilder } from '../core/normalize/index.ts';
import { enabledCustomRuleCount, enabledRuleCount, resolveConfig } from '../core/config/index.ts';
import type { ResolvedSecurityConfig } from '../core/config/index.ts';
import { addCoverage, emptyCoverage, sortCoverage } from '../core/coverage.ts';
import { compareTests, dedupeRun } from '../core/fingerprint/index.ts';
import {
  asciiTerminal,
  colorEnabled,
  DEFAULT_WIDTH,
  formatBanner,
  formatShardSummary,
} from '../core/report/console.ts';
import type { TerminalOptions } from '../core/report/console.ts';
import type {
  BaselineFile,
  Diagnostic,
  Finding,
  OutcomeFile,
  TestAttachment,
  TestContextRef,
} from '../core/types/index.ts';
import { ATTACHMENT_NAME } from '../collector/test-collector.ts';
import {
  CHECK_SKIP_REASON,
  isAttackMode,
  passiveMode,
  readAuthzEnv,
  readMaxTests,
  readMode,
  RUN_ID_ENV,
  SALT_ENV,
  ZAP_API_KEY_ENV,
} from '../mode/index.ts';
import type { ScanMode } from '../mode/index.ts';
import { removeCheckState } from '../collector/check-skip.ts';
import { formatCheck } from '../core/report/check.ts';
import type { CheckOrigin } from '../core/report/check.ts';
import { getRegistered } from '../registry/index.ts';
import { VERSION } from '../version.ts';
import { readCiInfo } from './ci-info.ts';
import { EnabledRules, finishRun, KNOWN_RULE_IDS, today } from './finish.ts';
import type { RunData } from './finish.ts';
import { isPartialRun } from './partial.ts';
import {
  configSnapshot,
  SHARD_FILE_FORMAT,
  SHARD_FILE_VERSION,
  shardFileName,
} from './shard-file.ts';
import type { ShardFile } from './shard-file.ts';

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
  /** Check (04-REQ-12): the last result of each test and the tests with API traffic. */
  readonly #results = new Map<string, { status: TestResult['status']; byCheck: boolean }>();
  readonly #withApi = new Set<string>();
  /** Request templates of the authorization tests (18-REQ-13). */
  readonly #templates: RequestTemplate[] = [];
  /** Request templates of the attack mode (19-REQ-03). */
  readonly #attackTemplates: AttackTemplate[] = [];
  /** stdout is a terminal: the attack progress overwrites one line (19-REQ-07). */
  readonly #tty: boolean;

  constructor(options: ReporterOptions = {}) {
    this.#write = options.write ?? ((line) => process.stdout.write(`${line}\n`));
    const out = options.stdout ?? process.stdout;
    const env = options.env ?? process.env;
    this.#tty = options.write === undefined && out.isTTY === true;
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

  #settings(): { config: ResolvedSecurityConfig; mode: ScanMode; scope: string[] } {
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

  /** Projects of the Playwright config for the roles (18-REQ-07). */
  #projects(): (ProjectInfo & { ignoreHTTPSErrors: boolean })[] {
    const state = getRegistered();
    const scanned = state?.scannedProjects;
    const all = state === undefined || state.config.scope.projects === 'all';
    return (this.#config?.projects ?? []).map((p) => {
      const use = p.use as { storageState?: unknown; ignoreHTTPSErrors?: boolean };
      return {
        name: p.name,
        storageState: typeof use.storageState === 'string' ? use.storageState : undefined,
        scanned: all || (scanned ?? []).includes(p.name),
        ignoreHTTPSErrors: use.ignoreHTTPSErrors === true,
      };
    });
  }

  /** The authorization tests of this run: null when authz.enabled is off (18-REQ-05). */
  #authz(sec: ResolvedSecurityConfig): { on: boolean; offByEnv: boolean; roles: Role[] } | null {
    if (!sec.authz.enabled) return null;
    const env = readAuthzEnv(process.env);
    const offByEnv = env.ok && env.off;
    return { on: !offByEnv, offByEnv, roles: rolesOf(this.#projects(), sec.authz) };
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
      const baselineName = sec.baseline.path;
      const file = this.#path(baselineName);
      if (existsSync(file)) {
        try {
          const parsed = JSON.parse(readFileSync(file, 'utf8')) as { findings?: object };
          entries = Object.keys(parsed.findings ?? {}).length;
        } catch {
          entries = 0;
        }
      }
      const authz = this.#authz(sec);
      if (authz?.on === true && authz.roles.length === 0) {
        const w: Diagnostic = {
          code: 'AUTHZ_NO_ROLES',
          level: 'warn',
          message:
            'authz: no project with storageState: only unauthenticated access is tested (docs/authz.md)',
        };
        this.#diag(w);
        notes.push(w);
      }
      let attackRow: string | undefined;
      if (isAttackMode(mode)) {
        const roles = rolesOf(this.#projects(), sec.authz).map((r) => r.name);
        attackRow = attackBannerText(sec.attack, attackRole(sec.attack, roles));
        const mutating = sec.attack.methods.filter((m) => MUTATING_METHODS.includes(m));
        if (mutating.length > 0) {
          const w: Diagnostic = {
            code: 'ATTACK_MUTATING_METHODS',
            level: 'warn',
            message: `attack.methods has ${mutating.join(', ')}: ZAP sends attacks with methods that change data; use an environment whose data may be changed (docs/attack.md)`,
          };
          this.#diag(w);
          notes.push(w);
        }
      }
      const shard = mode === 'check' ? null : config.shard;
      const reportFile =
        shard !== null ? shardFileName(shard) : sec.report.html ? 'report.html' : 'report.json';
      const banner = formatBanner(
        {
          mode,
          scope,
          enabledRules: enabledRuleCount(sec),
          customRules: enabledCustomRuleCount(sec),
          preset: sec.preset,
          minSeverity: sec.gate.minSeverity,
          minConfidence: sec.gate.minConfidence,
          baselinePath: baselineName,
          baselineEntries: entries,
          reportPath: `${sec.report.dir.replace(/[\\/]+$/, '')}/${reportFile}`,
          notes,
          shard,
          authz:
            authz === null
              ? undefined
              : { on: authz.on, text: authzBannerText(authz.roles, sec.authz, authz.offByEnv) },
          attack: attackRow,
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

  /** Every test of the run by id (09, chapter 3.7); empty before onBegin. */
  #testRefs(): Map<string, TestContextRef> {
    const refs = new Map<string, TestContextRef>();
    for (const test of this.#suite?.allTests() ?? []) refs.set(test.id, this.#ref(test));
    return refs;
  }

  onTestEnd(test: TestCase, result: TestResult): void {
    try {
      const annotations = [...test.annotations, ...(result.annotations ?? [])];
      this.#results.set(test.id, {
        status: result.status,
        byCheck: annotations.some((a) => a.description === CHECK_SKIP_REASON),
      });
      for (const a of result.attachments) {
        if (a.name === TEMPLATES_ATTACHMENT) {
          this.#readTemplates(a, test);
          continue;
        }
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
        if (doc.coverage.apiResponses > 0) this.#withApi.add(test.id);
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

  /** Templates of one test attempt (02-REQ-07); a later attempt does not add a key twice. */
  #readTemplates(a: TestResult['attachments'][number], test: TestCase): void {
    try {
      const text =
        a.body !== undefined
          ? a.body.toString('utf8')
          : a.path !== undefined
            ? readFileSync(a.path, 'utf8')
            : '';
      const doc = JSON.parse(text) as TemplatesAttachment;
      if (Array.isArray(doc.templates)) this.#templates.push(...doc.templates);
      if (Array.isArray(doc.attack)) this.#attackTemplates.push(...doc.attack);
    } catch {
      this.#diag({
        code: 'ATTACHMENT_INVALID',
        level: 'warn',
        message: `the request templates of "${test.title}" could not be read`,
        testId: test.id,
      });
    }
  }

  async onEnd(result: FullResult): Promise<{ status?: FullResult['status'] } | undefined> {
    try {
      return await this.#finish(result);
    } catch (error) {
      this.#write(
        `pw-sec: internal error: ${error instanceof Error ? error.message : String(error)}`,
      );
      return { status: 'failed' };
    }
  }

  /** The replay plan of this run (18-REQ-14). */
  #plan(sec: ResolvedSecurityConfig, roles: readonly Role[]): Plan {
    return planReplays(this.#templates, roles, this.#coverage.authzObserved ?? {}, sec);
  }

  /**
   * The replays after the tests (18, chapter 7): the module that sends requests is loaded only
   * here (18-REQ-06). Null when the tests are off.
   */
  async #replay(sec: ResolvedSecurityConfig, result: FullResult): Promise<AuthzRunData | null> {
    const authz = this.#authz(sec);
    if (authz === null || !authz.on) return null;
    const plan = this.#plan(sec, authz.roles);
    const data: AuthzRunData = {
      roles: authz.roles.map(({ headers: _h, ...r }) => r),
      templates: plan.templates,
      budget: { maxRequests: sec.authz.maxRequests, used: 0, exceeded: false },
      results: [],
      notes: plan.notes,
    };
    const toSend = plan.replays.filter((p) => p.decided === undefined).length;
    if (result.status === 'interrupted' || toSend === 0) {
      data.results = plan.replays.map(
        (p) => decidedResult(p) ?? resultOf(p, { result: 'skipped', reason: 'interrupted' }),
      );
      return data;
    }
    const salt = process.env[SALT_ENV] ?? getRegistered()?.salt ?? '';
    const { sendReplays } = await import('../active/index.ts');
    const out = await sendReplays(plan, {
      authz: sec.authz,
      roles: authz.roles,
      projects: this.#projects(),
      runId: process.env[RUN_ID_ENV] ?? getRegistered()?.runId ?? '',
      hash: authzHash(salt),
      configDir: this.#configDir(),
      maxBodyBytes: sec.limits.maxBodyBytes,
      diagnostic: (d) => this.#diag(d),
    });
    data.results = out.results;
    data.budget = { maxRequests: sec.authz.maxRequests, used: out.used, exceeded: out.exceeded };
    return data;
  }

  /** A check (04, chapter 4c): no file is written and the exit code stays Playwright's. */
  #finishCheck(sec: ResolvedSecurityConfig, scope: string[]): void {
    const state = getRegistered();
    const runId = process.env[RUN_ID_ENV] ?? state?.runId ?? '';
    if (runId !== '') removeCheckState(runId);
    const coverage = sortCoverage(this.#coverage);
    const findings = dedupeRun(this.#findings);
    const enabled = new EnabledRules(sec);
    const baselineName = sec.baseline.path;
    const baselinePath = this.#path(baselineName);
    let baseline: BaselineFile | undefined;
    let baselineState = `${baselineName} (not found)`;
    if (existsSync(baselinePath)) {
      const parsed = parseBaseline(
        readFileSync(baselinePath, 'utf8'),
        baselineName,
        KNOWN_RULE_IDS,
        enabled,
      );
      for (const d of parsed.diagnostics) this.#diag(d);
      if (parsed.ok) {
        baseline = parsed.file;
        const n = Object.keys(parsed.file.findings).length;
        baselineState = `${baselineName} (${n} ${n === 1 ? 'entry' : 'entries'})`;
      } else {
        baselineState = `${baselineName} (invalid: ${parsed.diagnostics[0]?.code ?? 'BASELINE_INVALID'})`;
      }
    }
    const classified = classify(findings, baseline, sec.gate, today(), true);
    const projects = state?.scannedProjects ?? [];
    const scanned = (test: TestCase): boolean =>
      sec.scope.projects === 'all' || projects.includes(test.parent.project()?.name ?? '');
    const tests = (this.#suite?.allTests() ?? []).filter(scanned);
    let ran = 0;
    let passed = 0;
    let failed = 0;
    let skipped = 0;
    for (const test of tests) {
      const r = this.#results.get(test.id);
      if (r === undefined) continue;
      if (r.byCheck) skipped += 1;
      else if (r.status !== 'skipped') {
        ran += 1;
        if (r.status === 'passed') passed += 1;
        else failed += 1;
      }
    }
    const baseOrigins = new Set(sec.scope.includeBaseURL ? (state?.baseOrigins ?? []) : []);
    const origins: CheckOrigin[] = scope.map((origin) => ({
      origin,
      source: baseOrigins.has(origin) ? 'baseURL' : 'scope.origins',
      responses: coverage.origins[origin]?.responses ?? 0,
      documents: coverage.origins[origin]?.documents ?? 0,
    }));
    const max = readMaxTests(process.env);
    // 18-REQ-19: the plan of the authorization tests, without sending a request.
    const authz = this.#authz(sec);
    const authzLine =
      authz === null
        ? undefined
        : authzCheckText(authz.roles, sec.authz, this.#plan(sec, authz.roles), authz.offByEnv);
    const lines = formatCheck(
      {
        shard: this.#config?.shard ?? null,
        tests: { ran, selected: tests.length, passed, failed, skipped },
        maxTests: max.ok ? max.maxTests : 10,
        origins,
        outOfScope: coverage.outOfScopeOrigins ?? {},
        responses: coverage.responses,
        apiResponses: coverage.apiResponses,
        testsWithApi: this.#withApi.size,
        projects,
        enabledRules: enabledRuleCount(sec),
        customRules: enabledCustomRuleCount(sec),
        preset: sec.preset,
        baseline: baselineState,
        findings: findings.length,
        newAboveGate: classified.filter((f) => f.classification === 'new' && f.blocking).length,
        minSeverity: sec.gate.minSeverity,
        diagnostics: [...this.#diagnostics.values()].filter((d) => d.code !== 'SCOPE_EMPTY'),
        authz: authzLine,
      },
      this.#terminal,
    );
    for (const line of lines) this.#write(line);
  }

  async #finish(result: FullResult): Promise<{ status?: FullResult['status'] } | undefined> {
    const { config: sec, mode, scope } = this.#settings();
    if (mode === 'check') {
      this.#finishCheck(sec, scope);
      return undefined;
    }
    let authz: AuthzRunData | null = null;
    try {
      authz = await this.#replay(sec, result);
    } catch (error) {
      this.#toolError('the authorization tests', error);
    }
    let attack: AttackRunData | null = null;
    try {
      attack = await this.#attack(sec, mode, result);
    } catch (error) {
      this.#toolError('the attack', error);
    }
    const shard = this.#config?.shard ?? null;
    if (shard !== null)
      return this.#finishShard(result, sec, passiveMode(mode), scope, shard, authz);
    const out = finishRun(this.#runData(result, authz, attack), {
      config: sec,
      mode,
      scope,
      runId: process.env[RUN_ID_ENV] ?? getRegistered()?.runId ?? '',
      startedAt: this.#startedAt.toISOString(),
      finishedAt: () => new Date().toISOString(),
      playwrightVersion: this.#config?.version ?? '',
      configDir: this.#configDir(),
      reportDir: this.#path(sec.report.dir),
      partial: isPartialRun(this.#config, this.#suite, process.argv),
      shards: null,
      tests: this.#testRefs(),
      write: this.#write,
      terminal: this.#terminal,
    });
    return out.code === 0 ? undefined : { status: 'failed' };
  }

  #runData(result: FullResult, authz: AuthzRunData | null, attack: AttackRunData | null): RunData {
    return {
      findings: this.#findings,
      coverage: this.#coverage,
      diagnostics: [...this.#diagnostics.values()],
      testsWithoutTraffic: [...this.#withoutTraffic.values()],
      testsPassed: result.status === 'passed',
      authz,
      attack,
    };
  }

  /**
   * The ZAP active scan after the tests (19, chapter 5): the module that drives ZAP is loaded only
   * here (P-04). Null outside the attack modes.
   */
  async #attack(
    sec: ResolvedSecurityConfig,
    mode: ScanMode,
    result: FullResult,
  ): Promise<AttackRunData | null> {
    if (!isAttackMode(mode)) return null;
    const a = sec.attack;
    const roles = rolesOf(this.#projects(), sec.authz);
    const roleName = attackRole(
      a,
      roles.map((r) => r.name),
    );
    if (result.status === 'interrupted') {
      this.#diag({
        code: 'ATTACK_INTERRUPTED',
        level: 'warn',
        message: 'attack: the run was interrupted, so ZAP did not scan',
      });
      return { summary: emptyAttackSummary(a, roleName), findings: [], coveredKeys: [] };
    }
    // One template per endpoint key, the first in the order of the tests (19 chapter 11a).
    const templates: AttackTemplate[] = [];
    const seen = new Set<string>();
    for (const t of [...this.#attackTemplates].sort(
      (x, y) =>
        compareTests(x.context, y.context) ||
        (x.endpointKey < y.endpointKey ? -1 : x.endpointKey > y.endpointKey ? 1 : 0),
    )) {
      if (seen.has(t.endpointKey)) continue;
      seen.add(t.endpointKey);
      templates.push(t);
    }
    const zap = await import('../active/zap.ts');
    let role: AttackRole | null = null;
    const found = roles.find((r) => r.name === roleName);
    if (found !== undefined) {
      const project = this.#projects().find((p) => p.name === found.projects[0]);
      const state = project?.storageState;
      const candidates =
        state === undefined
          ? []
          : isAbsolute(state)
            ? [state]
            : [resolve(this.#configDir(), state), resolve(process.cwd(), state)];
      const cookies = candidates.map((c) => zap.readStorageCookies(c)).find((c) => c !== null);
      if (cookies === undefined) {
        this.#diag({
          code: 'ATTACK_STATE_MISSING',
          level: 'warn',
          message: `attack: the storageState file of project ${found.projects[0] ?? ''} does not exist; ZAP scanned without a session`,
        });
      } else {
        role = {
          name: roleName,
          cookies,
          headers: {
            ...found.headers,
            ...(sec.authz.roles[found.projects[0] ?? '']?.headers ?? {}),
          },
        };
      }
    }
    const state = getRegistered();
    const keys = createKeyBuilder(sec.normalization, { baseOrigins: state?.baseOrigins ?? [] });
    const paramNames = sec.rules['data.token-in-url']?.options.paramNames;
    const redactor = new Redactor({
      salt: process.env[SALT_ENV] ?? state?.salt ?? '',
      paramNames: Array.isArray(paramNames) ? (paramNames as string[]) : [],
    });
    let lastLine = 0;
    let progressShown = false;
    const out = await zap.runAttack({
      attack: a,
      templates,
      runId: process.env[RUN_ID_ENV] ?? state?.runId ?? '',
      role,
      keyOf: (method, url) => {
        const origin = canonicalOrigin(url);
        const key = keys({ method, url, resourceType: 'xhr' });
        return origin === null || !key.ok ? null : { origin, key: key.key };
      },
      redact: (text) => redactor.text(text),
      diagnostic: (d) => this.#diag(d),
      progress: (line) => {
        if (this.#tty) {
          process.stdout.write(`\r${line}\u001b[K`);
          progressShown = true;
        } else if (Date.now() - lastLine >= zap.CI_PROGRESS_MS) {
          lastLine = Date.now();
          this.#write(line);
        }
      },
      zapApiKey: process.env[ZAP_API_KEY_ENV],
    });
    if (progressShown) process.stdout.write('\n');
    return out;
  }

  /**
   * A shard run (17, chapter 4): the shard file and outcome.json of the shard, no baseline, no
   * classification and no reports (17-REQ-02). The exit code stays Playwright's, 1 on code 3.
   */
  #finishShard(
    result: FullResult,
    sec: ResolvedSecurityConfig,
    mode: 'scan' | 'baseline',
    scope: string[],
    shard: { current: number; total: number },
    authz: AuthzRunData | null,
  ): { status?: FullResult['status'] } | undefined {
    const dir = this.#path(sec.report.dir);
    const file = join(dir, shardFileName(shard));
    const configFile = this.#config?.configFile;
    const configDir = this.#configDir();
    const cwd = process.cwd();
    const slash = (p: string): string => p.split('\\').join('/');
    const tests = { total: 0, passed: 0, failed: 0, flaky: 0, skipped: 0 };
    for (const test of this.#suite?.allTests() ?? []) {
      tests.total += 1;
      const outcome = test.outcome();
      if (outcome === 'expected') tests.passed += 1;
      else if (outcome === 'flaky') tests.flaky += 1;
      else if (outcome === 'skipped') tests.skipped += 1;
      else tests.failed += 1;
    }
    const data: ShardFile = {
      format: SHARD_FILE_FORMAT,
      schemaVersion: SHARD_FILE_VERSION,
      pkgVersion: VERSION,
      playwrightVersion: this.#config?.version ?? '',
      shard: { current: shard.current, total: shard.total },
      runId: process.env[RUN_ID_ENV] ?? getRegistered()?.runId ?? '',
      startedAt: this.#startedAt.toISOString(),
      finishedAt: new Date().toISOString(),
      mode,
      partial: isPartialRun(this.#config, this.#suite, process.argv),
      paths: {
        configDir: slash(relative(cwd, configDir)) || '.',
        configFile: configFile === undefined ? '' : basename(configFile),
        baselinePath: slash(sec.baseline.path),
      },
      config: configSnapshot(sec),
      scope,
      ci: readCiInfo(process.env),
      status: result.status,
      tests,
      findings: this.#findings,
      coverage: sortCoverage(this.#coverage),
      testsWithoutTraffic: [...this.#withoutTraffic.values()].sort(compareTests),
      diagnostics: [...this.#diagnostics.values()],
      authz,
    };
    let written = false;
    try {
      mkdirSync(dir, { recursive: true });
      // Atomic: the merge never reads half a file (17-REQ-07).
      const temp = `${file}.${process.pid}.tmp`;
      writeFileSync(temp, `${JSON.stringify(data)}\n`);
      renameSync(temp, file);
      written = true;
    } catch (error) {
      this.#diag({
        code: 'SHARD_WRITE_FAILED',
        level: 'error',
        message: `the shard file could not be written to ${file}: ${error instanceof Error ? error.message : String(error)}`,
      });
    }
    const diagnostics = [...this.#diagnostics.values()];
    const error = !written || diagnostics.some((d) => d.level === 'error');
    const out: OutcomeFile = {
      schemaVersion: 2,
      code: error ? 3 : 0,
      name: error ? 'TOOL_ERROR' : 'SHARD_WRITTEN',
      mode,
      shard: { current: shard.current, total: shard.total },
      testsPassed: result.status === 'passed',
      newBlocking: null,
      newNonBlocking: null,
      expired: null,
      resolved: null,
    };
    try {
      mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, 'outcome.json'), `${JSON.stringify(out, null, 2)}\n`);
    } catch (e) {
      this.#write(
        `pw-sec: could not write outcome.json: ${e instanceof Error ? e.message : String(e)}`,
      );
    }
    const rawFindings = dedupeRun(this.#findings).length;
    for (const line of formatShardSummary(
      {
        mode,
        shard,
        responses: data.coverage.responses,
        apiResponses: data.coverage.apiResponses,
        findings: rawFindings,
        dataPath: relative(cwd, file).split('\\').join('/'),
        diagnostics,
        code: out.code,
      },
      this.#terminal,
    ))
      this.#write(line);
    return out.code === 3 ? { status: 'failed' } : undefined;
  }
}
