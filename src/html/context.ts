// What the renderer needs besides the run report: rule docs, the resolved config and the tests of
// the run (09, chapter 3.7).
import type { ResolvedSecurityConfig } from '../core/config/index.ts';
import type { BuiltInRule } from '../core/rules/index.ts';
import type { RunReport, TestContextRef } from '../core/types/index.ts';

export interface HtmlReportInput {
  report: RunReport;
  /** Rules with their docs (Why, Fix, False positives) and manifest. */
  rules: readonly BuiltInRule[];
  /** The resolved config of the run for Run & config; null when unknown. */
  config: ResolvedSecurityConfig | null;
  /** Tests of the run by id: `tests` of a finding holds ids only (09, chapter 3.7). */
  tests?: ReadonlyMap<string, TestContextRef>;
}

export interface Ctx {
  report: RunReport;
  rules: ReadonlyMap<string, BuiltInRule>;
  config: ResolvedSecurityConfig | null;
  tests: ReadonlyMap<string, TestContextRef>;
  /** `YYYY-MM-DD` of the end of the run: the addedAt of a ready baseline entry. */
  today: string;
}

export function context(input: HtmlReportInput): Ctx {
  return {
    report: input.report,
    rules: new Map(input.rules.map((r) => [r.id, r])),
    config: input.config,
    tests: input.tests ?? new Map(),
    today: input.report.finishedAt.slice(0, 10),
  };
}
