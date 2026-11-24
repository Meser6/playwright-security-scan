// Report files besides report.json and outcome.json (09): HTML, SARIF and JUnit XML are added by
// their work packages. Each writer returns the path it wrote, or null.
import type { ResolvedSecurityConfig } from '../core/config/index.ts';
import type { RunReport } from '../core/types/index.ts';

export type ReportWriter = (
  report: RunReport,
  config: ResolvedSecurityConfig,
  dir: string,
) => string | null;

export const REPORT_WRITERS: { name: 'html' | 'sarif' | 'junit'; write: ReportWriter }[] = [];
