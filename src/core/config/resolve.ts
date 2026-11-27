// Resolution of the package config: defaults, presets (06, chapter 3) and per-rule settings.
import { resolveAttack } from '../attack/config.ts';
import type { ResolvedAttack } from '../attack/config.ts';
import { resolveAuthz } from '../authz/config.ts';
import { AUTHZ_MANIFEST } from '../authz/manifest.ts';
import { adaptCustomRule } from '../custom/adapt.ts';
import type { Rule as CustomRule } from '../custom/define.ts';
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
import { validateConfig, ZAP_RULE_ID } from './validate.ts';

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
  const customRules: readonly CustomRule[] = i.rules?.custom ?? [];
  // Presets and settings work on custom rules as on built-in ones (16-REQ-05).
  const manifests = [...RULE_MANIFEST, ...customRules.map((r) => adaptCustomRule(r).manifest)];
  for (const rule of manifests) {
    const setting = i.rules?.[rule.id] as RuleSetting | undefined;
    const base = presetRule(rule, preset);
    rules[rule.id] = setting === undefined ? base : applySetting(base, setting);
  }
  // Presets leave the authorization tests alone: authz.enabled decides (18 chapter 12a).
  for (const rule of AUTHZ_MANIFEST) {
    const setting = i.rules?.[rule.id] as RuleSetting | undefined;
    const base: ResolvedRule = {
      enabled: true,
      severity: rule.defaultSeverity,
      confidence: rule.defaultConfidence,
      options: {},
    };
    rules[rule.id] = setting === undefined ? base : applySetting(base, setting);
  }
  // zap.<pluginId> settings (19-REQ-09): kept apart from the rules, the alert gives the defaults.
  const zapRules: ResolvedAttack['rules'] = {};
  for (const [id, setting] of Object.entries(i.rules ?? {})) {
    if (!ZAP_RULE_ID.test(id) || setting === undefined) continue;
    const s = setting as RuleSetting;
    zapRules[id] = {
      enabled: s !== 'off',
      ...(typeof s === 'object' && s.severity !== undefined ? { severity: s.severity } : {}),
      ...(typeof s === 'object' && s.confidence !== undefined ? { confidence: s.confidence } : {}),
    };
  }
  const reportDir = i.report?.dir ?? DEFAULTS.report.dir;
  return {
    ok: true,
    config: {
      scope: { ...DEFAULTS.scope, ...i.scope },
      preset,
      rules,
      customRules,
      limits: { ...DEFAULTS.limits, ...i.limits },
      browser: { ...DEFAULTS.browser, ...i.browser },
      gate: { ...DEFAULTS.gate, ...i.gate },
      baseline: { ...DEFAULTS.baseline, ...i.baseline },
      report: {
        ...DEFAULTS.report,
        ...i.report,
        junitPath: i.report?.junitPath ?? `${reportDir.replace(/[\\/]+$/, '')}/junit.xml`,
      },
      normalization: resolveNormalization(i.normalization),
      authz: resolveAuthz(i.authz),
      attack: { ...resolveAttack(i.attack), rules: zapRules },
    },
  };
}

/** Number of enabled rules, for the start banner (04, chapter 3). */
export function enabledRuleCount(config: ResolvedSecurityConfig): number {
  // Without the authorization tests: they have their own banner line (18 chapter 12a).
  return Object.entries(config.rules).filter(([id, r]) => r.enabled && !id.startsWith('authz.'))
    .length;
}

/** Number of enabled custom rules, for the start banner (16-REQ-12). */
export function enabledCustomRuleCount(config: ResolvedSecurityConfig): number {
  return config.customRules.filter((r) => config.rules[r.id]?.enabled === true).length;
}
