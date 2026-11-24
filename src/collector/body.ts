// Reading bodies with limits (05, chapter 5.2).
import { createHash } from 'node:crypto';

/** Resource types whose bodies are never read (05-REQ-13). */
const NEVER = new Set([
  'image',
  'font',
  'media',
  'websocket',
  'eventsource',
  'manifest',
  'texttrack',
]);
/** Statuses without a body (05-REQ-10). */
const NO_BODY = new Set([204, 304]);
/** Static assets: read once per worker and cut to the limit (05-REQ-14, 05-AC-02). */
export const STATIC_TYPES = new Set(['script', 'stylesheet']);

/** content-type without parameters, lowercase. */
export function mediaType(contentType: string | undefined): string {
  return (contentType ?? '').split(';')[0]?.trim().toLowerCase() ?? '';
}

/** Whether `type` is on the list; `*+json` style entries match suffixes. */
export function typeAllowed(type: string, allowed: readonly string[]): boolean {
  return allowed.some((entry) =>
    entry.startsWith('*') ? type.endsWith(entry.slice(1)) : entry.toLowerCase() === type,
  );
}

export type SkipReason = 'resource-type' | 'status' | 'content-type' | 'too-large' | 'no-rule';

/** Why a body is not read, or null when it is (05-REQ-10, 05-REQ-13). */
export function bodySkipReason(input: {
  resourceType: string;
  status: number;
  contentType: string | undefined;
  contentLength: string | undefined;
  maxBodyBytes: number;
  allowedTypes: readonly string[];
  wanted: boolean;
}): SkipReason | null {
  if (NEVER.has(input.resourceType)) return 'resource-type';
  if (NO_BODY.has(input.status) || (input.status >= 300 && input.status < 400)) return 'status';
  if (!input.wanted) return 'no-rule';
  if (!typeAllowed(mediaType(input.contentType), input.allowedTypes)) return 'content-type';
  const length = Number(input.contentLength);
  // Static assets are cut to the limit instead (05-AC-02).
  if (
    !STATIC_TYPES.has(input.resourceType) &&
    Number.isFinite(length) &&
    length > input.maxBodyBytes
  ) {
    return 'too-large';
  }
  return null;
}

/** The view rules get: UTF-8 text cut to the limit, and the hash of the whole body. */
export function bodyView(
  bytes: Buffer,
  contentType: string | undefined,
  maxBodyBytes: number,
): { contentType: string; text: string; truncated: boolean; sha256: string } {
  const truncated = bytes.length > maxBodyBytes;
  const slice = truncated ? bytes.subarray(0, maxBodyBytes) : bytes;
  return {
    contentType: mediaType(contentType),
    text: slice.toString('utf8'),
    truncated,
    sha256: createHash('sha256').update(bytes).digest('hex'),
  };
}
