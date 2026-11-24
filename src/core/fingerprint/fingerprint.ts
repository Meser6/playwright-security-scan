// Fingerprints (07, chapter 3): readable, without hashing, so that baseline diffs can be reviewed.
import { sha256 } from '../hash/index.ts';
import type { FindingScope } from '../types/index.ts';

/** Longer fingerprints are shortened (07-REQ-08). */
export const MAX_FINGERPRINT_LENGTH = 512;
const KEPT_PREFIX = 480;

export interface FingerprintInput {
  ruleId: string;
  scope: FindingScope;
  subject: string;
  discriminator?: string | undefined;
}

/**
 * `ruleId|scope|subject[|discriminator]` (07-REQ-05). Severity and confidence are not part of it
 * (07-REQ-07). Over 512 characters: the first 480, `…#` and 8 hex digits of its SHA-256 (07-REQ-08).
 */
export function fingerprintOf(input: FingerprintInput): string {
  const parts = [input.ruleId, input.scope, input.subject];
  if (input.discriminator !== undefined && input.discriminator !== '')
    parts.push(input.discriminator);
  const full = parts.join('|');
  if (full.length <= MAX_FINGERPRINT_LENGTH) return full;
  return `${full.slice(0, KEPT_PREFIX)}…#${sha256(full).slice(0, 8)}`;
}
