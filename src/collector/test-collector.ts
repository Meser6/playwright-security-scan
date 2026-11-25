// The collector of one test (05, chapters 5.2, 6 and 8): runs the rules on records and browser
// events, keeps the redacted findings, coverage and diagnostics, and builds the attachment.
import { addCoverage, emptyCoverage } from '../core/coverage.ts';
import { dedupeTest, normalizeAssetUrl, toFinding } from '../core/fingerprint/index.ts';
import type { Redactor } from '../core/fingerprint/index.ts';
import type { ResolvedSecurityConfig } from '../core/config/index.ts';
import type { BuiltInRule, RuleContext } from '../core/rules/index.ts';
import type {
  BrowserEvent,
  Coverage,
  Diagnostic,
  Finding,
  RawFinding,
  ResponseRecord,
  Source,
  TestAttachment,
  TestContextRef,
} from '../core/types/index.ts';
import { isLocalOrigin } from './scope.ts';
import type { Scope } from './scope.ts';

export const ATTACHMENT_NAME = 'pw-sec-findings';
/** Maximum attachment size (02-REQ-05). */
export const MAX_ATTACHMENT_BYTES = 256 * 1024;
const MAX_CACHE_ENTRIES = 2000;

/**
 * Analysis cache of the worker (05-REQ-14): redacted results of body rules per rule, URL and body
 * hash of static assets; and the body hash per URL and validator, so an unchanged bundle is read
 * once per worker (05-AC-02). Bodies themselves are never kept (05-REQ-12).
 */
export class AnalysisCache {
  readonly #findings = new Map<string, RawFinding[]>();
  readonly #hashes = new Map<string, string>();

  findings(key: string): RawFinding[] | undefined {
    return this.#findings.get(key);
  }

  setFindings(key: string, value: RawFinding[]): void {
    if (this.#findings.size >= MAX_CACHE_ENTRIES) this.#findings.clear();
    this.#findings.set(key, value);
  }

  hash(key: string): string | undefined {
    return this.#hashes.get(key);
  }

  setHash(key: string, sha: string): void {
    if (this.#hashes.size >= MAX_CACHE_ENTRIES) this.#hashes.clear();
    this.#hashes.set(key, sha);
  }
}

export interface TestCollectorOptions {
  config: ResolvedSecurityConfig;
  rules: readonly BuiltInRule[];
  scope: Scope;
  redactor: Redactor;
  cache: AnalysisCache;
  test: TestContextRef;
}

export class TestCollector {
  readonly options: TestCollectorOptions;
  readonly coverage: Coverage = emptyCoverage();
  readonly #findings: Finding[] = [];
  readonly #diagnostics = new Map<string, Diagnostic>();
  /** Rules switched off for this test after an exception (05-REQ-15). */
  readonly #failed = new Set<string>();
  readonly #perRule = new Map<string, number>();
  readonly #enabled: BuiltInRule[];
  /** Resource types some enabled rule reads the body of (05-REQ-10). */
  readonly bodyTypes: ReadonlySet<string>;

  constructor(options: TestCollectorOptions) {
    this.options = options;
    this.#enabled = options.rules.filter((r) => options.config.rules[r.id]?.enabled === true);
    this.bodyTypes = new Set(this.#enabled.flatMap((r) => r.needsBody ?? []));
  }

  get test(): TestContextRef {
    return this.options.test;
  }

  diagnostic(code: string, level: Diagnostic['level'], message: string): void {
    const key = `${code}\u0000${message}`;
    if (!this.#diagnostics.has(key)) {
      this.#diagnostics.set(key, { code, level, message, testId: this.options.test.testId });
    }
  }

  skipBody(reason: string): void {
    this.coverage.bodiesSkipped[reason] = (this.coverage.bodiesSkipped[reason] ?? 0) + 1;
  }

  outOfScope(origin: string): void {
    this.coverage.outOfScope += 1;
    // Origins of the traffic outside the scope, for the check (04-REQ-13).
    const origins = (this.coverage.outOfScopeOrigins ??= {});
    origins[origin] = (origins[origin] ?? 0) + 1;
  }

  #context(rule: BuiltInRule, origin: string, isHttps: boolean): RuleContext {
    const resolved = this.options.config.rules[rule.id];
    const scope = this.options.scope;
    return {
      options: resolved?.options ?? {},
      severity: resolved?.severity ?? rule.manifest.defaultSeverity,
      confidence: resolved?.confidence ?? rule.manifest.defaultConfidence,
      localDev: isLocalOrigin(origin),
      isHttps,
      inScope: (o) => scope.has(o),
      redact: this.options.redactor,
    };
  }

  /** Runs one rule with error isolation (05-REQ-15, P-08) and redaction (05-REQ-16). */
  #run(rule: BuiltInRule, input: ResponseRecord | BrowserEvent, ctx: RuleContext): RawFinding[] {
    this.coverage.rulesRun[rule.id] = (this.coverage.rulesRun[rule.id] ?? 0) + 1;
    try {
      return rule.check(input, ctx).map((raw) => this.options.redactor.enforce(raw));
    } catch (error) {
      this.#failed.add(rule.id);
      this.diagnostic(
        'RULE_ERROR',
        'warn',
        `rule ${rule.id} threw and is off for the rest of this test: ${error instanceof Error ? error.message : String(error)}`,
      );
      return [];
    }
  }

  #add(raws: readonly RawFinding[], source: Source): void {
    const limit = this.options.config.limits.maxFindingsPerRule;
    for (const raw of raws) {
      const count = this.#perRule.get(raw.ruleId) ?? 0;
      if (count >= limit) {
        this.diagnostic(
          'RULE_FINDINGS_LIMIT',
          'warn',
          `rule ${raw.ruleId} reached limits.maxFindingsPerRule (${limit}) in this test; further findings were dropped`,
        );
        continue;
      }
      this.#perRule.set(raw.ruleId, count + 1);
      this.#findings.push(toFinding(raw, this.options.test, source));
    }
  }

  /** Counts a record in scope (02, chapter 6). */
  #count(record: ResponseRecord): void {
    const c = this.coverage;
    c.responses += 1;
    if (record.source === 'api') c.apiResponses += 1;
    const isDocument = record.resourceType === 'document';
    if (isDocument) c.documents += 1;
    const origin = (c.origins[record.origin] ??= { responses: 0, documents: 0 });
    origin.responses += 1;
    if (isDocument) origin.documents += 1;
    c.endpoints[record.endpointKey] = (c.endpoints[record.endpointKey] ?? 0) + 1;
    if (record.resourceType === 'script' || record.resourceType === 'stylesheet') {
      const asset = normalizeAssetUrl(record.url);
      if (asset !== null && !c.assets.includes(asset)) c.assets.push(asset);
    }
  }

  /**
   * Analyses an in-scope record (05-REQ-15). `cachedSha` is set when the body of a static asset
   * was not read because the worker already analysed it (05-REQ-14).
   */
  analyzeRecord(record: ResponseRecord, cachedSha?: string): void {
    this.#count(record);
    const isHttps = record.url.startsWith('https:');
    for (const rule of this.#enabled) {
      if (this.#failed.has(rule.id) || !applies(rule, record)) continue;
      const ctx = this.#context(rule, record.origin, isHttps);
      const readsBody = rule.needsBody?.includes(record.resourceType) === true;
      const sha = record.body?.sha256 ?? cachedSha;
      const cacheable =
        readsBody &&
        sha !== undefined &&
        (record.resourceType === 'script' || record.resourceType === 'stylesheet');
      const key = `${rule.id}\u0000${record.url}\u0000${sha ?? ''}`;
      if (cacheable && record.body === undefined) {
        this.#add(this.options.cache.findings(key) ?? [], record.source);
        continue;
      }
      const raws = this.#run(rule, record, ctx);
      if (cacheable) this.options.cache.setFindings(key, raws);
      this.#add(raws, record.source);
    }
  }

  /** Analyses an out-of-scope record with the rules that ask for it (05-REQ-05). */
  analyzeOutOfScope(record: ResponseRecord): void {
    for (const rule of this.#enabled) {
      if (this.#failed.has(rule.id) || rule.appliesTo.outOfScope !== true) continue;
      if (!applies(rule, record)) continue;
      const ctx = this.#context(rule, record.origin, record.url.startsWith('https:'));
      this.#add(this.#run(rule, record, ctx), record.source);
    }
  }

  /** Analyses a browser event (05, chapters 7 and 8). */
  analyzeEvent(event: BrowserEvent): void {
    if (event.kind === 'storage' && !this.coverage.storageOrigins.includes(event.origin)) {
      this.coverage.storageOrigins.push(event.origin);
    }
    const origin =
      event.kind === 'storage'
        ? event.origin
        : event.kind === 'csp-violation'
          ? event.documentOrigin
          : '';
    for (const rule of this.#enabled) {
      if (this.#failed.has(rule.id)) continue;
      if (rule.appliesTo.events?.includes(event.kind) !== true) continue;
      const ctx = this.#context(rule, origin, origin.startsWith('https:'));
      this.#add(this.#run(rule, event, ctx), 'browser');
    }
  }

  /** Adds coverage of work done elsewhere (e.g. the API wrapper). */
  addCoverage(coverage: Coverage): void {
    addCoverage(this.coverage, coverage);
  }

  findings(): Finding[] {
    return dedupeTest(this.#findings);
  }

  diagnostics(): Diagnostic[] {
    return [...this.#diagnostics.values()];
  }

  /** The attachment (02-REQ-05): at most 256 KB, else one evidence item per finding. */
  attachment(): string {
    const coverage = this.coverage;
    coverage.assets.sort();
    coverage.storageOrigins.sort();
    const doc: TestAttachment = {
      schemaVersion: 1,
      findings: this.findings(),
      coverage,
      diagnostics: this.diagnostics(),
    };
    let body = JSON.stringify(doc);
    if (Buffer.byteLength(body) > MAX_ATTACHMENT_BYTES) {
      doc.findings = doc.findings.map((f) => ({ ...f, evidence: f.evidence.slice(0, 1) }));
      doc.diagnostics.push({
        code: 'ATTACHMENT_TRUNCATED',
        level: 'warn',
        message:
          'the findings of this test exceeded 256 KB; evidence was cut to one item per finding',
        testId: this.options.test.testId,
      });
      body = JSON.stringify(doc);
    }
    return body;
  }
}

/** Whether a rule applies to a record (06, chapter 2). */
export function applies(rule: BuiltInRule, record: ResponseRecord): boolean {
  const to = rule.appliesTo;
  if (to.events !== undefined && to.events.length > 0 && to.records !== true) return false;
  if (to.sources !== undefined && !to.sources.includes(record.source)) return false;
  if (!rule.manifest.sources.includes(record.source)) return false;
  return to.resourceTypes === undefined || to.resourceTypes.includes(record.resourceType);
}
