// The package reporter (01-REQ-07), added by withSecurity() in scan and baseline mode. It collects
// the test attachments, compares the findings with the baseline and writes the reports (08, 09).
import type { Reporter } from '@playwright/test/reporter';

export default class SecurityReporter implements Reporter {
  printsToStdio(): boolean {
    return false;
  }
}
