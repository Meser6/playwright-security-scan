// Package config (03, chapter 4): what users write and the resolved form.
import type { NormalizationConfig, NormalizationInput } from '../normalize/index.ts';
import type { Confidence, Severity } from '../types/index.ts';

export type Preset = 'recommended' | 'strict' | 'minimal';

/** Per-rule setting (03, chapter 4). */
export type RuleSetting =
  | 'off'
  | 'on'
  | { severity?: Severity; confidence?: Confidence; options?: Record<string, unknown> };

/** Config accepted by defineSecurityConfig() and withSecurity(); every option is optional. */
export interface SecurityConfigInput {
  scope?: {
    origins?: string[];
    includeBaseURL?: boolean;
    exclude?: string[];
    projects?: string[] | 'all';
    api?: boolean;
  };
  rules?: { preset?: Preset } & { [ruleId: string]: RuleSetting | Preset | undefined };
  limits?: {
    maxBodyBytes?: number;
    bodyContentTypes?: string[];
    maxFindingsPerRule?: number;
  };
  browser?: { cspEvents?: boolean; storageScan?: boolean };
  gate?: {
    minSeverity?: Severity;
    minConfidence?: Confidence;
    failOnExpired?: boolean;
    failOnNoTraffic?: boolean;
  };
  baseline?: { path?: string; pruneResolved?: boolean; requireNote?: boolean };
  report?: {
    dir?: string;
    html?: boolean;
    json?: boolean;
    sarif?: boolean;
    junit?: boolean;
    junitPath?: string;
    junitIncludeAccepted?: boolean;
    sarifIncludeAccepted?: boolean;
  };
  normalization?: NormalizationInput;
}

export interface ResolvedRule {
  enabled: boolean;
  severity: Severity;
  confidence: Confidence;
  options: Record<string, unknown>;
}

export interface ResolvedSecurityConfig {
  scope: {
    origins: string[];
    includeBaseURL: boolean;
    exclude: string[];
    projects: string[] | 'all';
    api: boolean;
  };
  preset: Preset;
  rules: Record<string, ResolvedRule>;
  limits: { maxBodyBytes: number; bodyContentTypes: string[]; maxFindingsPerRule: number };
  browser: { cspEvents: boolean; storageScan: boolean };
  gate: {
    minSeverity: Severity;
    minConfidence: Confidence;
    failOnExpired: boolean;
    failOnNoTraffic: boolean;
  };
  baseline: { path: string; pruneResolved: boolean; requireNote: boolean };
  report: {
    dir: string;
    html: boolean;
    json: boolean;
    sarif: boolean;
    junit: boolean;
    junitPath: string;
    junitIncludeAccepted: boolean;
    sarifIncludeAccepted: boolean;
  };
  normalization: NormalizationConfig;
}

/** A config problem; `path` is the option path, e.g. "rules.cookie.no-htponly". */
export interface ConfigIssue {
  code: string;
  path: string;
  message: string;
  hint?: string;
}
