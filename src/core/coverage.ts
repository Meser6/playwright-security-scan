// Coverage counters (02, chapter 6): built per test in the worker, summed in the reporter.
import type { Coverage } from './types/index.ts';

export function emptyCoverage(): Coverage {
  return {
    responses: 0,
    apiResponses: 0,
    outOfScope: 0,
    documents: 0,
    bodiesAnalyzed: 0,
    bodiesSkipped: {},
    endpoints: {},
    origins: {},
    assets: [],
    storageOrigins: [],
    rulesRun: {},
  };
}

function addCounts(into: Record<string, number>, from: Readonly<Record<string, number>>): void {
  for (const [key, value] of Object.entries(from)) into[key] = (into[key] ?? 0) + value;
}

function sortKeys<T>(record: Record<string, T>): Record<string, T> {
  return Object.fromEntries(
    Object.keys(record)
      .sort()
      .map((k) => [k, record[k] as T]),
  );
}

/** Adds `from` to `into` (mutates `into`). */
export function addCoverage(into: Coverage, from: Coverage): void {
  into.responses += from.responses;
  into.apiResponses += from.apiResponses;
  into.outOfScope += from.outOfScope;
  if (from.outOfScopeOrigins !== undefined) {
    into.outOfScopeOrigins ??= {};
    addCounts(into.outOfScopeOrigins, from.outOfScopeOrigins);
  }
  into.documents += from.documents;
  into.bodiesAnalyzed += from.bodiesAnalyzed;
  addCounts(into.bodiesSkipped, from.bodiesSkipped);
  addCounts(into.endpoints, from.endpoints);
  addCounts(into.rulesRun, from.rulesRun);
  for (const [origin, counts] of Object.entries(from.origins)) {
    const current = (into.origins[origin] ??= { responses: 0, documents: 0 });
    current.responses += counts.responses;
    current.documents += counts.documents;
  }
  into.assets = [...new Set([...into.assets, ...from.assets])];
  into.storageOrigins = [...new Set([...into.storageOrigins, ...from.storageOrigins])];
}

/** The same coverage with sorted keys and lists, for deterministic output (P-06). */
export function sortCoverage(coverage: Coverage): Coverage {
  return {
    ...coverage,
    bodiesSkipped: sortKeys(coverage.bodiesSkipped),
    endpoints: sortKeys(coverage.endpoints),
    rulesRun: sortKeys(coverage.rulesRun),
    ...(coverage.outOfScopeOrigins === undefined
      ? {}
      : { outOfScopeOrigins: sortKeys(coverage.outOfScopeOrigins) }),
    origins: sortKeys(coverage.origins),
    assets: [...coverage.assets].sort(),
    storageOrigins: [...coverage.storageOrigins].sort(),
  };
}
