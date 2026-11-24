// The `normalization` option (03, chapter 4): the same settings and defaults as the `keys`
// section of the perf package config (07-REQ-01, ADR-0006).

/** A problem found while building a key; collected by the caller. */
export interface Issue {
  code: string;
  message: string;
  hint?: string;
}

/** A string matches a whole path segment literally; a RegExp is tested against it. */
export type IdPattern = string | RegExp;

export interface KeyBuilderInput {
  /** Uppercase HTTP method. */
  method: string;
  /** Raw URL. */
  url: string;
  resourceType: string;
}

/** Returns a whole key, or undefined for the built-in normalization. */
export type KeyBuilder = (req: KeyBuilderInput) => string | undefined;

/** Resolved normalization settings: every option has a value. */
export interface NormalizationConfig {
  /** Origin to label mapping; a key with `*` is a host pattern. */
  origins: Record<string, string>;
  idPatterns: {
    number: boolean;
    uuid: boolean;
    hex: boolean;
    token: boolean;
    mixed: boolean;
    prefixed: boolean;
    email: boolean;
  };
  extraIdPatterns: IdPattern[];
  query: 'names' | 'ignore';
  keepQueryValues: string[];
  dropQueryParams: string[];
  keyBuilder?: KeyBuilder;
}

/** What a user may give: every option optional; regexes also as { regex, flags }. */
export interface NormalizationInput {
  origins?: Record<string, string>;
  idPatterns?: Partial<NormalizationConfig['idPatterns']>;
  extraIdPatterns?: (IdPattern | { regex: string; flags?: string })[];
  query?: 'names' | 'ignore';
  keepQueryValues?: string[];
  dropQueryParams?: string[];
  keyBuilder?: KeyBuilder;
}

/** Defaults of the perf package `keys` section (perf config schema). */
export const NORMALIZATION_DEFAULTS: Readonly<NormalizationConfig> = Object.freeze({
  origins: {},
  idPatterns: {
    number: true,
    uuid: true,
    hex: true,
    token: true,
    mixed: true,
    prefixed: true,
    email: true,
  },
  extraIdPatterns: [],
  query: 'names',
  keepQueryValues: [],
  dropQueryParams: [],
});

function compilePattern(pattern: IdPattern | { regex: string; flags?: string }): IdPattern {
  if (typeof pattern === 'string') return pattern;
  if (pattern instanceof RegExp)
    return new RegExp(pattern.source, pattern.flags.replace(/[gy]/g, ''));
  return new RegExp(pattern.regex, (pattern.flags ?? '').replace(/[gy]/g, ''));
}

/**
 * Merges `input` into the defaults. Types were validated before (03-REQ-02); regexes lose
 * their g/y flags as in the perf package (07-REQ-09 of the perf spec).
 */
export function resolveNormalization(input: NormalizationInput = {}): NormalizationConfig {
  const config: NormalizationConfig = {
    origins: { ...(input.origins ?? {}) },
    idPatterns: { ...NORMALIZATION_DEFAULTS.idPatterns, ...(input.idPatterns ?? {}) },
    extraIdPatterns: (input.extraIdPatterns ?? []).map(compilePattern),
    query: input.query ?? 'names',
    keepQueryValues: [...(input.keepQueryValues ?? [])],
    dropQueryParams: [...(input.dropQueryParams ?? [])],
  };
  if (input.keyBuilder !== undefined) config.keyBuilder = input.keyBuilder;
  return config;
}
