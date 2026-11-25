// Validation of the package config (03-REQ-02): unknown options and rule ids with the closest
// known name, wrong types and values with the allowed ones. Every problem is reported (P-12).
import { canonicalOrigin, parseHostPattern } from '../normalize/index.ts';
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
/** Environment label (08-REQ-13), as PW_PERF_ENV in the perf package. */
export const ENV_LABEL = /^[a-z0-9][a-z0-9-]{0,31}$/;
export const ENV_LABEL_HINT =
  'Use 1 to 32 lowercase letters, digits and "-", starting with a letter or a digit (e.g. "qa", "staging-eu").';
const envLabel: Check = (c, p, v) => {
  if (typeof v !== 'string') c.type(p, v, 'a string');
  else if (!ENV_LABEL.test(v)) {
    c.add(
      'CONFIG_INVALID_VALUE',
      p,
      `${JSON.stringify(v)} is not an environment label`,
      ENV_LABEL_HINT,
    );
  }
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

function ruleSetting(c: Collector, path: string, id: string, value: unknown): void {
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
      const defaults = ruleManifest(id)?.options ?? {};
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
  for (const [key, v] of Object.entries(value)) {
    if (key === 'preset') {
      enumOf(PRESETS)(c, 'rules.preset', v);
      continue;
    }
    if (!RULE_IDS.includes(key)) {
      const suggestion = closest(key, RULE_IDS);
      c.add(
        'CONFIG_UNKNOWN_RULE',
        `rules.${key}`,
        suggestion === undefined
          ? 'unknown rule id'
          : `unknown rule id. Did you mean "${suggestion}"?`,
        'Rule ids are listed in docs/rules/README.md of the package.',
      );
      continue;
    }
    if (v !== undefined) ruleSetting(c, `rules.${key}`, key, v);
  }
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
    run: (cc, p, v) => section(cc, p, v, { env: envLabel }),
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
