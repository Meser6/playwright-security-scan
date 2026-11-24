// Entry point `playwright-security-scan/reporter` (01, chapter 5). withSecurity() adds it to the
// reporters in scan mode. The named export keeps the CJS build an exports object with `default`,
// matching its declarations (as in the perf package).
import SecurityReporter from '../reporter/index.ts';

export { SecurityReporter };
export default SecurityReporter;
