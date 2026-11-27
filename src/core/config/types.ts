// Package config (03, chapter 4): what users write and the resolved form.
import type { AuthzInput, ResolvedAuthz } from '../authz/config.ts';
import type { Rule as CustomRule } from '../custom/define.ts';
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
  rules?: {
    preset?: Preset;
    /** Custom rules made with defineRule() (16-REQ-04). @experimental */
    custom?: readonly CustomRule[];
  } & { [ruleId: string]: RuleSetting | Preset | readonly CustomRule[] | undefined };
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
  /** Authorization tests (18-REQ-01); off by default. */
  authz?: AuthzInput;
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
  /** Custom rules from rules.custom, in their order (16-REQ-07). */
  customRules: readonly CustomRule[];
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
  authz: ResolvedAuthz;
}

/** A config problem; `path` is the option path, e.g. "rules.cookie.no-htponly". */
export interface ConfigIssue {
  code: string;
  path: string;
  message: string;
  hint?: string;
}
