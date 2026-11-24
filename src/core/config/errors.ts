// ConfigError: thrown by withSecurity() before any test runs (03-REQ-02, P-12).
import type { ConfigIssue } from './types.ts';

export const PACKAGE_NAME = 'playwright-security-scan';

export class ConfigError extends Error {
  readonly issues: ConfigIssue[];

  constructor(issues: ConfigIssue[]) {
    const count = `${issues.length} ${issues.length === 1 ? 'problem' : 'problems'}`;
    super(
      [
        `${PACKAGE_NAME}: invalid configuration (${count})`,
        ...issues.flatMap((issue) => [
          `  - ${issue.message}`,
          ...(issue.hint === undefined ? [] : [`    ${issue.hint}`]),
        ]),
      ].join('\n'),
    );
    this.name = 'ConfigError';
    this.issues = issues;
  }
}
