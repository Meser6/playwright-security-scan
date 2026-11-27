// SARIF and JUnit writers of the reporter (09, chapters 5 and 6).
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { buildJunit } from '../core/report/junit.ts';
import { buildSarif } from '../core/report/sarif.ts';
import { BUILT_IN_RULES } from '../core/rules/index.ts';
import { renderHtmlReport } from '../html/index.ts';
import { VERSION } from '../version.ts';
import type { ReportWriter } from './writers.ts';

export const writeSarif: ReportWriter = (report, config, paths) => {
  if (!config.report.sarif) return null;
  const enabled = BUILT_IN_RULES.filter((r) => config.rules[r.id]?.enabled === true);
  const path = join(paths.reportDir, 'results.sarif');
  const log = buildSarif(report, enabled, {
    version: VERSION,
    includeAccepted: config.report.sarifIncludeAccepted,
  });
  writeFileSync(path, `${JSON.stringify(log, null, 2)}\n`);
  return path;
};

/** report.junitPath is relative to the directory of the Playwright config, like report.dir. */
export const writeJunit: ReportWriter = (report, config, paths) => {
  if (!config.report.junit) return null;
  const path = isAbsolute(config.report.junitPath)
    ? config.report.junitPath
    : resolve(paths.configDir, config.report.junitPath);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(
    path,
    buildJunit(report, BUILT_IN_RULES, {
      includeAccepted: config.report.junitIncludeAccepted,
      failOnExpired: config.gate.failOnExpired,
    }),
  );
  return path;
};

/** report.html: one offline file (09, chapter 3.6). */
export const writeHtml: ReportWriter = (report, config, paths) => {
  if (!config.report.html) return null;
  const path = join(paths.reportDir, 'report.html');
  writeFileSync(
    path,
    renderHtmlReport({
      report,
      rules: BUILT_IN_RULES,
      config,
      ...(paths.tests === undefined ? {} : { tests: paths.tests }),
    }),
  );
  return path;
};

/** The writers the reporter runs, in order (09). */
export const REPORT_WRITERS: { name: 'html' | 'sarif' | 'junit'; write: ReportWriter }[] = [
  { name: 'html', write: writeHtml },
  { name: 'sarif', write: writeSarif },
  { name: 'junit', write: writeJunit },
];
