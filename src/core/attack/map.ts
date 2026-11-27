// ZAP alerts → findings zap.<pluginId> (19-REQ-08, 19 chapter 11a). Pure: the key builder and the
// redaction come in, so the same alerts give the same findings (P-06).
import { compareTests, dedupeRun, toFinding } from '../fingerprint/index.ts';
import type {
  AttackSummary,
  Confidence,
  Finding,
  RawFinding,
  Severity,
  Source,
} from '../types/index.ts';
import { attackOriginAllowed } from './config.ts';
import type { ResolvedAttack } from './config.ts';
import type { AttackTemplate, ZapAlert } from './types.ts';

export const ZAP_DOCS = 'https://www.zaproxy.org/docs/alerts/';
/** Length limit of the ZAP texts kept in the report (19-REQ-08). */
export const MAX_ZAP_TEXT = 2000;

const RISK: Record<string, Severity> = {
  '3': 'high',
  high: 'high',
  '2': 'medium',
  medium: 'medium',
  '1': 'low',
  low: 'low',
  '0': 'info',
  informational: 'info',
  info: 'info',
};

/** Confidence of an alert; null for False Positive (19-REQ-08). */
export function confidenceOf(value: string): Confidence | null {
  const v = value.trim().toLowerCase();
  if (v === '4' || v === '3' || v === 'confirmed' || v === 'high') return 'high';
  if (v === '2' || v === 'medium') return 'medium';
  if (v === '1' || v === 'low') return 'low';
  return null;
}

export function severityOf(value: string): Severity {
  return RISK[value.trim().toLowerCase()] ?? 'info';
}

/** OWASP Top 10 id from the alert tags: 2025 first, else 2021 (`A05:2025`). */
export function owaspOf(tags: Record<string, string> | undefined): string | null {
  const keys = Object.keys(tags ?? {});
  for (const year of ['2025', '2021']) {
    const key = keys.find((k) => new RegExp(`^OWASP_${year}_A\\d\\d$`).test(k));
    if (key !== undefined) return `${key.slice(-3)}:${year}`;
  }
  return null;
}

const cut = (text: string | undefined): string => {
  const t = (text ?? '').trim();
  return t.length <= MAX_ZAP_TEXT ? t : `${t.slice(0, MAX_ZAP_TEXT - 1)}…`;
};

export interface MapOptions {
  attack: ResolvedAttack;
  /** Templates in the order they were sent: firstSeen and sources (19 chapter 11a). */
  templates: readonly AttackTemplate[];
  /** Origin and endpoint key of a request, by the normalization of the run (07); null: none. */
  keyOf(method: string, url: string): { origin: string; key: string } | null;
  /** Redaction of evidence and messages (07-REQ-13). */
  redact(text: string): string;
}

export interface MapResult {
  findings: Finding[];
  rules: AttackSummary['rules'];
  alerts: Pick<AttackSummary['alerts'], 'mapped' | 'falsePositive' | 'off'>;
}

/** Maps the alerts of one active scan to findings (19-REQ-08). */
export function mapAlerts(alerts: readonly ZapAlert[], o: MapOptions): MapResult {
  const byKey = new Map<string, AttackTemplate[]>();
  const byOrigin = new Map<string, AttackTemplate>();
  for (const t of o.templates) {
    const list = byKey.get(t.endpointKey) ?? [];
    list.push(t);
    byKey.set(t.endpointKey, list);
    if (!byOrigin.has(t.origin)) byOrigin.set(t.origin, t);
  }
  const rules = new Map<string, AttackSummary['rules'][number]>();
  const findings: Finding[] = [];
  let falsePositive = 0;
  let off = 0;
  let mapped = 0;
  for (const alert of alerts) {
    const confidence = confidenceOf(alert.confidence);
    if (confidence === null) {
      falsePositive += 1;
      continue;
    }
    if (!/^\d+$/.test(alert.pluginId)) continue;
    const ruleId = `zap.${alert.pluginId}`;
    const setting = o.attack.rules[ruleId];
    if (setting?.enabled === false) {
      off += 1;
      continue;
    }
    const where = o.keyOf((alert.method ?? 'GET').toUpperCase(), alert.url);
    if (where === null || !attackOriginAllowed(where.origin, o.attack)) continue;
    const templates = byKey.get(where.key);
    const first = templates?.[0] ?? byOrigin.get(where.origin) ?? o.templates[0];
    if (first === undefined) continue;
    const name = (alert.name ?? alert.alert ?? ruleId).trim();
    const param = (alert.param ?? '').trim();
    const parts = [
      alert.attack ? `attack: ${alert.attack}` : '',
      alert.evidence ? `evidence: ${alert.evidence}` : '',
    ].filter((p) => p !== '');
    const raw: RawFinding = {
      ruleId,
      severity: setting?.severity ?? severityOf(alert.risk),
      confidence: setting?.confidence ?? confidence,
      scope: 'endpoint',
      subject: where.key,
      ...(param === '' ? {} : { discriminator: param }),
      location: {
        origin: where.origin,
        endpointKey: where.key,
        ...(param === '' ? {} : { param }),
      },
      evidence: [
        {
          kind: 'attack',
          ...(param === '' ? {} : { name: param }),
          snippet: o.redact(parts.length === 0 ? name : parts.join(' · ')),
        },
      ],
      message: o.redact(`${name}${param === '' ? '' : ` in parameter ${param}`}`),
    };
    const sources = [...new Set<Source>((templates ?? [first]).map((t) => t.source))].sort();
    const finding = toFinding(raw, first.context, sources[0] ?? 'browser');
    finding.sources = sources.length === 0 ? ['browser'] : sources;
    findings.push(finding);
    mapped += 1;
    if (!rules.has(ruleId)) {
      const cwe = Number(alert.cweid);
      rules.set(ruleId, {
        id: ruleId,
        name,
        description: cut(alert.description),
        solution: cut(alert.solution),
        helpUri: `${ZAP_DOCS}${alert.pluginId}/`,
        cwe: Number.isInteger(cwe) && cwe > 0 ? [cwe] : [],
        owasp: owaspOf(alert.tags),
      });
    }
  }
  const sorted = [...findings].sort(
    (a, b) => compareTests(a.firstSeen, b.firstSeen) || (a.fingerprint < b.fingerprint ? -1 : 1),
  );
  return {
    findings: dedupeRun(sorted),
    rules: [...rules.values()].sort((a, b) => Number(a.id.slice(4)) - Number(b.id.slice(4))),
    alerts: { mapped, falsePositive, off },
  };
}
