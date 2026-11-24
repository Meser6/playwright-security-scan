// Fingerprints, deduplication and redaction (07).
export {
  compareTests,
  dedupeRun,
  dedupeTest,
  MAX_EVIDENCE,
  MAX_TESTS,
  toFinding,
} from './dedup.ts';
export { fingerprintOf, MAX_FINGERPRINT_LENGTH } from './fingerprint.ts';
export type { FingerprintInput } from './fingerprint.ts';
export {
  cookieSubject,
  normalizeAssetUrl,
  normalizeCookieDomain,
  normalizeName,
  normalizeOrigin,
} from './names.ts';
export {
  isSensitiveHeader,
  MAX_SNIPPET,
  Redactor,
  SENSITIVE_PARAMS,
  SNIPPET_CONTEXT,
  truncate,
} from './redact.ts';
export type { RedactorOptions } from './redact.ts';
