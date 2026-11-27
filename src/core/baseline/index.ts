// Baseline and gate (08).
export {
  classify,
  covered,
  EXPIRY_WARNING_DAYS,
  missingNotes,
  outcome,
  parseFingerprint,
  resolveEntries,
} from './evaluate.ts';
export type { Gate } from './evaluate.ts';
export { parseBaseline } from './parse.ts';
export type { BaselineParse } from './parse.ts';
export { serializeBaseline, updateBaseline } from './write.ts';
export type { BaselineDiff } from './write.ts';
