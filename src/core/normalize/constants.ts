// Copied from playwright-performance-regression@1.0.0 (commit 3895766), src/core/normalize,
// to keep endpoint keys identical to the perf package (D-08, 01-REQ-11, 07-REQ-01). Change it only
// together with the perf package; the golden cases in test/golden/normalize guard the copy.
// Documented constants of the built-in normalization (07; P-13).

/** Version of the built-in rules; part of the normalization fingerprint (07-REQ-21). */
export const NORMALIZE_RULES_VERSION = 2;
/** Longer keys are truncated, in UTF-16 code units (07-REQ-18). */
export const MAX_KEY_LENGTH = 2000;
/** Keys from one template that trigger NORMALIZE_HIGH_CARDINALITY (07-REQ-22). */
export const CARDINALITY_MIN_KEYS = 10;
/** More endpoint keys in a run trigger NORMALIZE_TOO_MANY_KEYS (07-REQ-22). */
export const MAX_KEYS_WARNING = 1000;
