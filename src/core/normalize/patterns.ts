// Copied from playwright-performance-regression@1.0.0 (commit 3895766), src/core/normalize,
// to keep endpoint keys identical to the perf package (D-08, 01-REQ-11, 07-REQ-01). Change it only
// together with the perf package; the golden cases in test/golden/normalize guard the copy.
// Id patterns matched against whole decoded path segments and query parts (07, chapter 7).
import type { NormalizationConfig } from './config.ts';

type BuiltInPattern = keyof NormalizationConfig['idPatterns'];

/** Built-in pattern expressions (07-REQ-08); documented constants (P-13). */
export const ID_PATTERNS: Readonly<Record<BuiltInPattern, RegExp>> = {
  number: /^[0-9]+$/,
  uuid: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
  hex: /^[0-9a-f]{16,}$/i,
  token:
    /^(?=[^0-9]*[0-9])(?:[A-Za-z0-9~=]{24,}|(?=[^a-z]*[a-z])(?=[^A-Z]*[A-Z])[A-Za-z0-9_.~=-]{24,})$/,
  mixed: /^(?=[^0-9]*[0-9])(?=[^a-z]*[a-z])(?=[^A-Z]*[A-Z])[A-Za-z0-9_-]{16,}$/,
  prefixed:
    /^(?:[A-Z]{2,5}-[0-9]{3,}|[a-z]{1,8}_(?:[0-9]{2,32}|(?=[A-Za-z]*[0-9])[A-Za-z0-9]{8,32}))$/,
  email: /^[^@\s/]+@[^@\s/]+\.[^@\s/]+$/,
};

export type IdMatcher = (text: string) => ':id' | ':email' | null;

/**
 * Compiles the enabled patterns once. `:email` wins over every other pattern; the order of the
 * other patterns does not change the result (07-REQ-10). A string extra pattern matches the whole
 * text; a RegExp is tested as given (its g/y flags were dropped by resolveConfig, 07-REQ-09).
 */
export function compileIdMatcher(keys: NormalizationConfig): IdMatcher {
  const email = keys.idPatterns.email ? ID_PATTERNS.email : undefined;
  const ids: ((text: string) => boolean)[] = [];
  for (const name of ['number', 'uuid', 'hex', 'token', 'mixed', 'prefixed'] as const) {
    if (keys.idPatterns[name]) {
      const re = ID_PATTERNS[name];
      ids.push((text) => re.test(text));
    }
  }
  for (const pattern of keys.extraIdPatterns) {
    if (typeof pattern === 'string') {
      ids.push((text) => text === pattern);
    } else {
      // Defensive copy without g/y for patterns not compiled by resolveConfig.
      const re = new RegExp(pattern.source, pattern.flags.replace(/[gy]/g, ''));
      ids.push((text) => re.test(text));
    }
  }
  return (text) => {
    if (email?.test(text) === true) return ':email';
    return ids.some((test) => test(text)) ? ':id' : null;
  };
}
