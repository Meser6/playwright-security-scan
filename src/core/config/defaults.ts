// Defaults of the package config (03, chapter 4; P-13).
import type { ResolvedSecurityConfig } from './types.ts';

export const DEFAULT_BODY_CONTENT_TYPES: readonly string[] = [
  'text/html',
  'application/json',
  '*+json',
  'text/javascript',
  'application/javascript',
  'text/plain',
  'application/xml',
  'text/xml',
];

export const DEFAULTS: Omit<
  ResolvedSecurityConfig,
  'rules' | 'customRules' | 'normalization' | 'authz'
> = {
  scope: { origins: [], includeBaseURL: true, exclude: [], projects: 'all', api: true },
  preset: 'recommended',
  limits: {
    maxBodyBytes: 1_048_576,
    bodyContentTypes: [...DEFAULT_BODY_CONTENT_TYPES],
    maxFindingsPerRule: 200,
  },
  browser: { cspEvents: true, storageScan: true },
  gate: {
    minSeverity: 'medium',
    minConfidence: 'medium',
    failOnExpired: true,
    failOnNoTraffic: true,
  },
  baseline: { path: 'security-baseline.json', pruneResolved: true, requireNote: false },
  report: {
    dir: 'reports/pw-sec',
    html: true,
    json: true,
    sarif: true,
    junit: true,
    junitPath: 'reports/pw-sec/junit.xml',
    junitIncludeAccepted: true,
    sarifIncludeAccepted: false,
  },
};
