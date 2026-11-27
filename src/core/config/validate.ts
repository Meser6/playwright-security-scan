// Validation of the package config (03-REQ-02): unknown options and rule ids with the closest
// known name, wrong types and values with the allowed ones. Every problem is reported (P-12).
import { deniedReason, resolveAuthz } from '../authz/config.ts';
import { AUTHZ_RULE_IDS } from '../authz/manifest.ts';
import { canonicalOrigin, parseHostPattern } from '../normalize/index.ts';
import { customRulesIssues, isCustomRule } from '../custom/define.ts';
import { RULE_IDS, ruleManifest } from '../manifest/rules.ts';
import { CONFIDENCES, SEVERITIES } from '../types/index.ts';
import type { ConfigIssue } from './types.ts';

const PRESETS = ['recommended', 'strict', 'minimal'] as const;
const MAX_SUGGESTION_DISTANCE = 3;

/** Levenshtein distance. */
export function editDistance(a: string, b: string): number {
  const row = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let previous = row[0] ?? 0;
    row[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const current = row[j] ?? 0;
      row[j] = Math.min(
        (row[j] ?? 0) + 1,
        (row[j - 1] ?? 0) + 1,
        previous + (a[i - 1] === b[j - 1] ? 0 : 1),
      );
      previous = current;
    }
  }
  return row[b.length] ?? 0;
}

/** The closest candidate within a small edit distance, if any. */
export function closest(name: string, candidates: readonly string[]): string | undefined {
  let best: { name: string; distance: number } | undefined;
  for (const candidate of candidates) {
    const distance = editDistance(name.toLowerCase(), candidate.toLowerCase());
    if (distance <= MAX_SUGGESTION_DISTANCE && (best === undefined || distance < best.distance)) {
      best = { name: candidate, distance };
    }
  }
  return best?.name;
}

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

const show = (v: unknown): string => {
  if (v instanceof RegExp) return String(v);
  if (typeof v === 'function') return 'a function';
  try {
    return JSON.stringify(v) ?? String(v);
  } catch {
    return String(v);
  }
};

class Collector {
  readonly issues: ConfigIssue[] = [];

  add(code: string, path: string, message: string, hint?: string): void {
    this.issues.push({
      code,
      path,
      message: `${path === '' ? 'config' : path}: ${message}`,
      ...(hint === undefined ? {} : { hint }),
    });
  }

  unknown(path: string, key: string, known: readonly string[]): void {
    const suggestion = closest(key, known);
    const full = path === '' ? key : `${path}.${key}`;
    this.add(
      'CONFIG_UNKNOWN_OPTION',
      full,
      suggestion === undefined ? 'unknown option' : `unknown option. Did you mean "${suggestion}"?`,
      `Allowed here: ${known.join(', ')}.`,
    );
  }

  type(path: string, value: unknown, expected: string): void {
    this.add('CONFIG_INVALID_TYPE', path, `expected ${expected}, got ${show(value)}`);
  }

  oneOf(path: string, value: unknown, allowed: readonly unknown[]): void {
    this.add(
      'CONFIG_INVALID_VALUE',
      path,
      `invalid value ${show(value)}`,
      `Allowed values: ${allowed.map((a) => show(a)).join(', ')}.`,
    );
  }
}

type Check = (c: Collector, path: string, value: unknown) => void;

const bool: Check = (c, p, v) => {
  if (typeof v !== 'boolean') c.type(p, v, 'true or false');
};
const positiveInt: Check = (c, p, v) => {
  if (typeof v !== 'number' || !Number.isInteger(v) || v <= 0) c.type(p, v, 'a positive integer');
};
const nonEmptyString: Check = (c, p, v) => {
  if (typeof v !== 'string' || v.trim() === '') c.type(p, v, 'a non-empty string');
};
const stringList: Check = (c, p, v) => {
  if (!Array.isArray(v) || v.some((x) => typeof x !== 'string' || x === '')) {
    c.type(p, v, 'an array of non-empty strings');
  }
};
const enumOf =
  (allowed: readonly string[]): Check =>
  (c, p, v) => {
    if (typeof v !== 'string' || !allowed.includes(v)) c.oneOf(p, v, allowed);
  };

/** An origin or a host pattern with `*` in a subdomain (03, chapter 4). */
const originList: Check = (c, p, v) => {
  if (!Array.isArray(v)) {
    c.type(p, v, 'an array of origins');
    return;
  }
  v.forEach((item, i) => {
    const path = `${p}[${i}]`;
    if (typeof item !== 'string') {
      c.type(path, item, 'an origin such as "https://api.example.com"');
      return;
    }
    const valid = item.includes('*')
      ? typeof parseHostPattern(item, '') !== 'string'
      : canonicalOrigin(item) !== null;
    if (!valid) {
      c.add(
        'CONFIG_INVALID_VALUE',
        path,
        `${show(item)} is not an origin`,
        'Use scheme://host[:port], e.g. "https://api.example.com" or "https://*.example.com".',
      );
    }
  });
};

function section(c: Collector, path: string, value: unknown, fields: Record<string, Check>): void {
  if (value === undefined) return;
  if (!isRecord(value)) {
    c.type(path, value, 'an object');
    return;
  }
  const known = Object.keys(fields);
  for (const [key, v] of Object.entries(value)) {
    const check = fields[key];
    if (check === undefined) c.unknown(path, key, known);
    else if (v !== undefined) check(c, `${path}.${key}`, v);
  }
}

const sameKind = (a: unknown, b: unknown): boolean =>
  Array.isArray(a) ? Array.isArray(b) : typeof a === typeof b && !Array.isArray(b);

function ruleSetting(
  c: Collector,
  path: string,
  id: string,
  value: unknown,
  defaults: Record<string, unknown>,
): void {
  if (value === 'off' || value === 'on') return;
  if (!isRecord(value)) {
    c.type(path, value, '"off", "on" or { severity?, confidence?, options? }');
    return;
  }
  section(c, path, value, {
    severity: enumOf(SEVERITIES),
    confidence: enumOf(CONFIDENCES),
    options: (cc, p, options) => {
      if (!isRecord(options)) {
        cc.type(p, options, 'an object');
        return;
      }
      const known = Object.keys(defaults);
      for (const [key, v] of Object.entries(options)) {
        if (!(key in defaults)) {
          if (known.length === 0) {
            cc.add('CONFIG_UNKNOWN_OPTION', `${p}.${key}`, `rule ${id} has no options`);
          } else cc.unknown(p, key, known);
        } else if (!sameKind(defaults[key], v)) {
          const expected = Array.isArray(defaults[key]) ? 'an array' : `a ${typeof defaults[key]}`;
          cc.type(`${p}.${key}`, v, expected);
        }
      }
    },
  });
}

function rules(c: Collector, value: unknown): void {
  if (value === undefined) return;
  if (!isRecord(value)) {
    c.type('rules', value, 'an object');
    return;
  }
  // Custom rules (16-REQ-04): ids and option defaults of the valid ones.
  const custom = new Map<string, Record<string, unknown>>();
  if (value.custom !== undefined) {
    c.issues.push(...customRulesIssues(value.custom));
    if (Array.isArray(value.custom)) {
      for (const rule of value.custom as unknown[]) {
        if (isCustomRule(rule)) custom.set(rule.id, { ...(rule.options ?? {}) });
      }
    }
  }
  const ids = [...RULE_IDS, ...AUTHZ_RULE_IDS, ...custom.keys()];
  for (const [key, v] of Object.entries(value)) {
    if (key === 'preset') {
      enumOf(PRESETS)(c, 'rules.preset', v);
      continue;
    }
    if (key === 'custom') continue;
    const defaults =
      custom.get(key) ??
      ruleManifest(key)?.options ??
      (AUTHZ_RULE_IDS.includes(key) ? {} : undefined);
    if (defaults === undefined) {
      const suggestion = closest(key, ids);
      c.add(
        'CONFIG_UNKNOWN_RULE',
        `rules.${key}`,
        suggestion === undefined
          ? 'unknown rule id'
          : `unknown rule id. Did you mean "${suggestion}"?`,
        key.startsWith('custom.')
          ? 'A custom rule must be listed in rules.custom.'
          : 'Rule ids are listed in docs/rules/README.md of the package.',
      );
      continue;
    }
    if (v !== undefined) ruleSetting(c, `rules.${key}`, key, v, defaults);
  }
}

/** Exact origins only: the hard check of 18-REQ-04 compares origins exactly (18 chapter 12a). */
const exactOriginList: Check = (c, p, v) => {
  if (!Array.isArray(v)) {
    c.type(p, v, 'an array of origins');
    return;
  }
  v.forEach((item, i) => {
    if (typeof item !== 'string' || item.includes('*') || canonicalOrigin(item) === null) {
      c.add(
        'CONFIG_INVALID_VALUE',
        `${p}[${i}]`,
        `${show(item)} is not an origin`,
        'Use scheme://host[:port] without wildcards, e.g. "https://staging.example.com".',
      );
    }
  });
};

const positiveNumber: Check = (c, p, v) => {
  if (typeof v !== 'number' || !Number.isFinite(v) || v <= 0) c.type(p, v, 'a positive number');
};

function authz(c: Collector, value: unknown): void {
  section(c, 'authz', value, {
    enabled: bool,
    allowedOrigins: exactOriginList,
    denyOrigins: exactOriginList,
    iUnderstandThisIsNotProduction: bool,
    roles: (cc, p, v) => {
      if (!isRecord(v)) {
        cc.type(p, v, 'an object of project name → role options');
        return;
      }
      for (const [project, options] of Object.entries(v)) {
        section(cc, `${p}.${project}`, options, {
          role: nonEmptyString,
          level: (c3, p3, v3) => {
            if (typeof v3 !== 'number' || !Number.isInteger(v3) || v3 < 0)
              c3.type(p3, v3, 'a whole number ≥ 0');
          },
          headers: (c3, p3, v3) => {
            if (!isRecord(v3) || Object.values(v3).some((x) => typeof x !== 'string'))
              c3.type(p3, v3, 'an object of header name → value');
          },
          skip: bool,
        });
      }
    },
    exclude: stringList,
    maxRequests: positiveInt,
    maxRps: positiveNumber,
    maxDurationMinutes: positiveNumber,
    similarity: (cc, p, v) => {
      if (typeof v !== 'number' || !(v >= 0 && v <= 1)) cc.type(p, v, 'a number from 0 to 1');
    },
    probeHeader: bool,
    tests: (cc, p, v) =>
      section(cc, p, v, { unauthenticated: bool, horizontal: bool, vertical: bool }),
  });
  if (
    !isRecord(value) ||
    value.enabled !== true ||
    c.issues.some((i) => i.path.startsWith('.authz'))
  )
    return;
  // 18-REQ-02: no default on purpose (R-05).
  const allowed = value.allowedOrigins;
  if (!Array.isArray(allowed) || allowed.length === 0) {
    c.add(
      'AUTHZ_ORIGINS_REQUIRED',
      '.authz.allowedOrigins',
      'authorization tests are enabled but authz.allowedOrigins is empty',
      'List the origins the package may send its GET/HEAD replays to, e.g. allowedOrigins: ["https://staging.example.com"]. There is no default on purpose.',
    );
    return;
  }
  // 18-REQ-03: the production block list, before any test runs.
  const resolved = resolveAuthz(value as Parameters<typeof resolveAuthz>[0]);
  resolved.allowedOrigins.forEach((origin, i) => {
    const reason = deniedReason(origin, resolved);
    if (reason === null) return;
    c.add(
      'AUTHZ_ORIGIN_DENIED',
      `.authz.allowedOrigins[${i}]`,
      `${origin} matches ${reason}; the package never sends requests to production`,
      reason === 'authz.denyOrigins'
        ? 'Remove it from authz.allowedOrigins: authz.denyOrigins always wins.'
        : 'Use a test environment. If this origin is not production, set authz.iUnderstandThisIsNotProduction: true.',
    );
  });
}

function normalization(c: Collector, value: unknown): void {
  section(c, 'normalization', value, {
    origins: (cc, p, v) => {
      if (!isRecord(v) || Object.values(v).some((x) => typeof x !== 'string')) {
        cc.type(p, v, 'an object of origin → label');
      }
    },
    idPatterns: (cc, p, v) =>
      section(cc, p, v, {
        number: bool,
        uuid: bool,
        hex: bool,
        token: bool,
        mixed: bool,
        prefixed: bool,
        email: bool,
      }),
    extraIdPatterns: (cc, p, v) => {
      if (!Array.isArray(v)) {
        cc.type(p, v, 'an array of strings and regexes');
        return;
      }
      v.forEach((item, i) => {
        if (typeof item === 'string' || item instanceof RegExp) return;
        if (isRecord(item) && typeof item.regex === 'string') {
          try {
            new RegExp(item.regex, typeof item.flags === 'string' ? item.flags : '');
          } catch (error) {
            cc.add('CONFIG_INVALID_REGEX', `${p}[${i}]`, String(error));
          }
          return;
        }
        cc.type(`${p}[${i}]`, item, 'a string, a RegExp or { regex, flags }');
      });
    },
    query: enumOf(['names', 'ignore']),
    keepQueryValues: stringList,
    dropQueryParams: stringList,
    keyBuilder: (cc, p, v) => {
      if (typeof v !== 'function') cc.type(p, v, 'a function');
    },
  });
}

/** Problems of a package config; an empty list means it is valid (03-REQ-02). */
export function validateConfig(input: unknown): ConfigIssue[] {
  const c = new Collector();
  if (input === undefined) return [];
  if (!isRecord(input)) {
    c.type('', input, 'an object (the default export of pw-sec.config.ts)');
    return c.issues;
  }
  const top: Record<string, Check> = {
    scope: (cc, p, v) =>
      section(cc, p, v, {
        origins: originList,
        includeBaseURL: bool,
        exclude: originList,
        projects: (c3, p3, v3) => {
          if (v3 !== 'all') stringList(c3, p3, v3);
        },
        api: bool,
      }),
    rules: (cc, _p, v) => rules(cc, v),
    limits: (cc, p, v) =>
      section(cc, p, v, {
        maxBodyBytes: positiveInt,
        bodyContentTypes: stringList,
        maxFindingsPerRule: positiveInt,
      }),
    browser: (cc, p, v) => section(cc, p, v, { cspEvents: bool, storageScan: bool }),
    gate: (cc, p, v) =>
      section(cc, p, v, {
        minSeverity: enumOf(SEVERITIES),
        minConfidence: enumOf(CONFIDENCES),
        failOnExpired: bool,
        failOnNoTraffic: bool,
      }),
    baseline: (cc, p, v) =>
      section(cc, p, v, { path: nonEmptyString, pruneResolved: bool, requireNote: bool }),
    report: (cc, p, v) =>
      section(cc, p, v, {
        dir: nonEmptyString,
        html: bool,
        json: bool,
        sarif: bool,
        junit: bool,
        junitPath: nonEmptyString,
        junitIncludeAccepted: bool,
        sarifIncludeAccepted: bool,
      }),
    normalization: (cc, _p, v) => normalization(cc, v),
    authz: (cc, _p, v) => authz(cc, v),
  };
  section(c, '', input, top);
  // section() prefixes top-level paths with '.'; strip it.
  for (const issue of c.issues) {
    if (issue.path.startsWith('.')) {
      issue.path = issue.path.slice(1);
      issue.message = issue.message.replace(/^\./, '');
    }
  }
  return c.issues;
}
