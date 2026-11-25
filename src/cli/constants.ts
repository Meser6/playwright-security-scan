// Names and links of the wizard and the binary (11). Kept apart from src/core: the CLI is an edge.
export const PACKAGE_NAME = 'playwright-security-scan';
export const BINARY_NAME = 'pw-sec';
export const INIT_COMMAND = `npm init ${PACKAGE_NAME}`;
export const REPOSITORY_URL = 'https://github.com/Meser6/playwright-security-scan';
export const DOCS_URL = `${REPOSITORY_URL}/blob/main/docs`;
/** Package config files: pw-sec.config.<ext> (03-REQ-04, 11-REQ-08). */
export const CONFIG_FILE_BASENAME = 'pw-sec.config';
export const CONFIG_FILE_EXTENSIONS: readonly string[] = [
  '.ts',
  '.mts',
  '.cts',
  '.js',
  '.mjs',
  '.cjs',
  '.json',
];
export const REPORT_DIR = 'reports/pw-sec';

/** A problem the CLI reports: code, message and an optional hint. */
export interface CliIssue {
  code: string;
  message: string;
  hint?: string;
}
export type Issue = CliIssue;

export type Result<T, E> = { ok: true; value: T } | { ok: false; issues: E[] };

/** Lowest supported @playwright/test (peer dependency, D-07); a test keeps it equal to package.json. */
export const MIN_PLAYWRIGHT_VERSION = '1.57.0';
