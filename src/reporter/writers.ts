// Report files besides report.json and outcome.json (09). Each writer returns the path it wrote,
// or null when the report is switched off.
import type { ResolvedSecurityConfig } from '../core/config/index.ts';
import type { RunReport } from '../core/types/index.ts';

export interface ReportPaths {
  /** Absolute report.dir. */
  reportDir: string;
  /** Directory of the Playwright config; relative option paths start there. */
  configDir: string;
}

export type ReportWriter = (
  report: RunReport,
  config: ResolvedSecurityConfig,
  paths: ReportPaths,
) => string | null;
