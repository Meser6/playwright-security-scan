// Resolution of the package config: defaults, presets (06, chapter 3) and per-rule settings.
import { RULE_MANIFEST } from '../manifest/rules.ts';
import type { RuleManifest } from '../manifest/rules.ts';
import { resolveNormalization } from '../normalize/index.ts';
import type { Confidence, Severity } from '../types/index.ts';
import { DEFAULTS } from './defaults.ts';
import type {
  ConfigIssue,
  Preset,
  ResolvedRule,
  ResolvedSecurityConfig,
  RuleSetting,
  SecurityConfigInput,
} from './types.ts';
import { validateConfig } from './validate.ts';

/** Severity and enablement of a rule in a preset (06, chapter 3). */
export function presetRule(rule: RuleManifest, preset: Preset): ResolvedRule {
  let severity: Severity = rule.defaultSeverity;
  const confidence: Confidence = rule.defaultConfidence;
  let enabled = !rule.strictOnly;
  if (preset === 'minimal') enabled = enabled && confidence === 'high';
  if (preset === 'strict') {
    enabled = true;
    if (severity === 'info') severity = 'low';
    else if (severity === 'low' && confidence === 'high') severity = 'medium';
  }
  return { enabled, severity, confidence, options: structuredClone(rule.options) };
}

function applySetting(base: ResolvedRule, setting: RuleSetting): ResolvedRule {
  if (setting === 'off') return { ...base, enabled: false };
  if (setting === 'on') return { ...base, enabled: true };
  return {
    enabled: true,
    severity: setting.severity ?? base.severity,
    confidence: setting.confidence ?? base.confidence,
    options: { ...base.options, ...(setting.options ?? {}) },
  };
}

export type ResolveResult =
  { ok: true; config: ResolvedSecurityConfig } | { ok: false; issues: ConfigIssue[] };

/** Validates `input` and resolves it into a config where every option has a value. */
export function resolveConfig(input: SecurityConfigInput | undefined): ResolveResult {
  const issues = validateConfig(input);
  if (issues.length > 0) return { ok: false, issues };
  const i = input ?? {};
  const preset: Preset = i.rules?.preset ?? DEFAULTS.preset;
  const rules: Record<string, ResolvedRule> = {};
  for (const rule of RULE_MANIFEST) {
    const setting = i.rules?.[rule.id] as RuleSetting | undefined;
    const base = presetRule(rule, preset);
    rules[rule.id] = setting === undefined ? base : applySetting(base, setting);
  }
  const reportDir = i.report?.dir ?? DEFAULTS.report.dir;
  return {
    ok: true,
    config: {
      scope: { ...DEFAULTS.scope, ...i.scope },
      preset,
      rules,
      limits: { ...DEFAULTS.limits, ...i.limits },
      browser: { ...DEFAULTS.browser, ...i.browser },
      gate: { ...DEFAULTS.gate, ...i.gate },
      baseline: { ...DEFAULTS.baseline, ...i.baseline },
      run: { env: i.run?.env ?? DEFAULTS.run.env },
      report: {
        ...DEFAULTS.report,
        ...i.report,
        junitPath: i.report?.junitPath ?? `${reportDir.replace(/[\\/]+$/, '')}/junit.xml`,
      },
      normalization: resolveNormalization(i.normalization),
    },
  };
}

/** Number of enabled rules, for the start banner (04, chapter 3). */
export function enabledRuleCount(config: ResolvedSecurityConfig): number {
  return Object.values(config.rules).filter((r) => r.enabled).length;
}
