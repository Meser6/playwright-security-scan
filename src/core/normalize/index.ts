// Endpoint key normalization (07, chapter 2.1): a copy of the perf package module (D-08).
export { MAX_KEY_LENGTH } from './constants.ts';
export { NORMALIZATION_DEFAULTS, resolveNormalization } from './config.ts';
export type {
  IdPattern,
  Issue,
  KeyBuilder,
  KeyBuilderInput,
  NormalizationConfig,
  NormalizationInput,
} from './config.ts';
export {
  canonicalOrigin,
  canonicalOrigins,
  coveredByOrigins,
  createKeyBuilder,
  originLabels,
  truncateKey,
} from './key-builder.ts';
export type { KeyBuilderContext, KeyResult, KeySample } from './key-builder.ts';
export { isHostPattern, matchingPattern, parseHostPattern } from './host-patterns.ts';
export type { HostPattern } from './host-patterns.ts';
