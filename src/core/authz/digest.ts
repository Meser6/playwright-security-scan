// Response digests and the comparison of a replay with the original (18-REQ-12, 18-REQ-15). Pure:
// the salted hash comes in as a function, so the worker and the reporter hash alike and no value
// can be recovered from a digest across runs (07-REQ-15). The text of a body never leaves here.
import { decodeJwt } from '../patterns/jwt.ts';
import { EMAIL_IN_TEXT } from '../patterns/pii.ts';
import type { Header } from '../types/index.ts';

/** 8 hex characters of a salted SHA-256 (18-REQ-12). */
export type HashFn = (text: string) => string;

export type DigestKind = 'json' | 'html' | 'other';

export interface ResponseDigest {
  status: number;
  kind: DigestKind;
  length: number;
  keyPaths?: string[];
  leaves?: string[];
  words?: string[];
  markers: string[];
}

/** Items of each hash set (18-REQ-12). */
export const MAX_DIGEST_ITEMS = 2000;
/** Leaf values longer than this are not hashed as path + value pairs (18-REQ-12). */
export const MAX_LEAF_LENGTH = 200;
const MARKER_CLAIMS = ['sub', 'email', 'user_id', 'uid'] as const;
const PROFILE_SEGMENT = /^(?:me|profile|account)$/i;

export interface DigestInput {
  status: number;
  /** content-type of the response, lowercase, without parameters. */
  contentType: string;
  /** The body as text; undefined when it was not read (then `kind: other`). */
  body: string | undefined;
  /** Body length in bytes (content-length when the body was not read). */
  length: number;
  /** Path of the request URL, for the profile markers. */
  path: string;
  /** Headers of the original request, for the JWT markers; none for a replay. */
  requestHeaders?: readonly Header[];
}

const isJsonType = (type: string): boolean => type === 'application/json' || type.endsWith('+json');

function parseJson(text: string): { ok: true; value: unknown } | { ok: false } {
  try {
    return { ok: true, value: JSON.parse(text) as unknown };
  } catch {
    return { ok: false };
  }
}

/** Key paths (`items[].id`) and leaf values of a JSON value, in document order. */
function walkJson(
  value: unknown,
  path: string,
  out: { paths: Set<string>; leaves: Set<string>; values: Set<string> },
): void {
  if (out.paths.size >= MAX_DIGEST_ITEMS && out.leaves.size >= MAX_DIGEST_ITEMS) return;
  if (Array.isArray(value)) {
    const p = `${path}[]`;
    for (const item of value) walkJson(item, p, out);
    return;
  }
  if (typeof value === 'object' && value !== null) {
    for (const [key, child] of Object.entries(value)) {
      const p = path === '' ? key : `${path}.${key}`;
      if (out.paths.size < MAX_DIGEST_ITEMS) out.paths.add(p);
      walkJson(child, p, out);
    }
    return;
  }
  const text = value === null ? 'null' : String(value);
  if (text.length <= MAX_LEAF_LENGTH) {
    if (out.leaves.size < MAX_DIGEST_ITEMS) out.leaves.add(`${path}=${text}`);
    if (out.values.size < MAX_DIGEST_ITEMS) out.values.add(text);
  }
}

/** Words of the visible text of a page: no tags, scripts or styles (18-REQ-12). */
export function visibleWords(html: string): string[] {
  const text = html
    .replace(/<(script|style|noscript|template)\b[\s\S]*?<\/\1\s*>/gi, ' ')
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<[^>]*>/g, ' ')
    .replace(/&(?:nbsp|amp|lt|gt|quot|#\d+|#x[0-9a-f]+);/gi, ' ')
    .toLowerCase();
  const words = new Set<string>();
  for (const m of text.matchAll(/[\p{L}\p{N}]+/gu)) {
    if (words.size >= MAX_DIGEST_ITEMS) break;
    words.add(m[0]);
  }
  return [...words];
}

/** Identifier claims of JWTs in the authorization and cookie headers (18-REQ-12). */
function jwtMarkers(headers: readonly Header[]): string[] {
  const out: string[] = [];
  for (const h of headers) {
    if (h.name !== 'authorization' && h.name !== 'cookie') continue;
    for (const m of h.value.matchAll(/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g)) {
      const payload = decodeJwt(m[0])?.payload;
      if (payload === null || payload === undefined) continue;
      for (const claim of MARKER_CLAIMS) {
        const v = payload[claim];
        if (typeof v === 'string' || typeof v === 'number') out.push(String(v));
      }
    }
  }
  return out;
}

const emails = (text: string): string[] =>
  [...text.matchAll(new RegExp(EMAIL_IN_TEXT.source, 'gi'))].map((m) => m[0].toLowerCase());

const sortedHashes = (items: Iterable<string>, hash: HashFn): string[] =>
  [...new Set([...items].map(hash))].sort();

/** What the body of a response is, for the digest. */
function kindOf(input: DigestInput): DigestKind {
  if (input.body === undefined) return 'other';
  if (isJsonType(input.contentType)) return parseJson(input.body).ok ? 'json' : 'other';
  if (input.contentType === 'text/html' || input.contentType === 'application/xhtml+xml')
    return 'html';
  return 'other';
}

/** The digest of a response (18-REQ-12): salted hashes only, never text. */
export function digestResponse(input: DigestInput, hash: HashFn): ResponseDigest {
  const kind = kindOf(input);
  const digest: ResponseDigest = { status: input.status, kind, length: input.length, markers: [] };
  const markers = jwtMarkers(input.requestHeaders ?? []);
  if (kind === 'json' && input.body !== undefined) {
    const out = { paths: new Set<string>(), leaves: new Set<string>(), values: new Set<string>() };
    walkJson((parseJson(input.body) as { value: unknown }).value, '', out);
    digest.keyPaths = sortedHashes(out.paths, hash);
    digest.leaves = sortedHashes(out.leaves, hash);
    if (input.path.split('/').some((s) => PROFILE_SEGMENT.test(s)))
      markers.push(...emails(input.body));
  } else if (kind === 'html' && input.body !== undefined) {
    digest.words = sortedHashes(visibleWords(input.body), hash);
  }
  digest.markers = sortedHashes(
    markers.map((m) => (m.includes('@') ? m.toLowerCase() : m)),
    hash,
  ).slice(0, MAX_DIGEST_ITEMS);
  return digest;
}

/** Jaccard similarity of two sets; two empty sets are equal (18 chapter 12a). */
export function jaccard(a: readonly string[], b: readonly string[]): number {
  if (a.length === 0 && b.length === 0) return 1;
  const left = new Set(a);
  let both = 0;
  const right = new Set(b);
  for (const item of right) if (left.has(item)) both += 1;
  return both / (left.size + right.size - both);
}

export type ReplayVerdict = 'denied' | 'similar' | 'different';

export interface ReplayResponse {
  status: number;
  contentType: string;
  body: string | undefined;
  length: number;
  path: string;
}

export interface Comparison {
  verdict: ReplayVerdict;
  /** Rounded to two decimals; absent for a denial. */
  similarity?: number;
  /** The replay carries an identifier of the original user (18-D-03). */
  markers: boolean;
  kind: DigestKind;
}

const DENIED_STATUS = new Set([401, 403, 404, 405]);

/** An empty list, or an object with only empty lists (18-REQ-15). */
function emptyJson(value: unknown): boolean {
  if (value === null) return true;
  if (Array.isArray(value)) return value.length === 0;
  if (typeof value === 'object') {
    return Object.values(value).every((v) => Array.isArray(v) && v.length === 0);
  }
  return false;
}

/** A sign-in page: a password field, or login/sign in in the title (18-REQ-15). */
function signInPage(html: string): boolean {
  if (/<input\b[^>]*\btype\s*=\s*["']?password\b/i.test(html)) return true;
  const title = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(html)?.[1] ?? '';
  return /\b(?:log ?in|sign ?in)\b/i.test(title);
}

const round = (n: number): number => Math.round(n * 100) / 100;

/**
 * Compares the response of a replay with the digest of the original (18-REQ-15): a denial, a
 * similar answer (only that can give a finding) or a different one.
 */
export function compareReplay(
  original: ResponseDigest,
  replay: ReplayResponse,
  hash: HashFn,
  threshold: number,
): Comparison {
  const status = replay.status;
  const digest = digestResponse({ ...replay }, hash);
  const denied: Comparison = { verdict: 'denied', markers: false, kind: digest.kind };
  if (DENIED_STATUS.has(status) || (status >= 300 && status < 400) || status >= 500) return denied;
  if (digest.kind === 'json' && replay.body !== undefined) {
    const parsed = parseJson(replay.body);
    if (parsed.ok && emptyJson(parsed.value)) return denied;
  }
  if (digest.kind === 'html' && replay.body !== undefined && signInPage(replay.body)) return denied;

  // Markers of the original user: hashes of the leaf values and e-mails of the replay.
  let markers = false;
  if (original.markers.length > 0 && replay.body !== undefined) {
    const values = new Set<string>();
    if (digest.kind === 'json') {
      const out = { paths: new Set<string>(), leaves: new Set<string>(), values };
      walkJson((parseJson(replay.body) as { value: unknown }).value, '', out);
    }
    for (const e of emails(replay.body)) values.add(e);
    const hashed = new Set([...values].map((v) => hash(v.includes('@') ? v.toLowerCase() : v)));
    markers = original.markers.some((m) => hashed.has(m));
  }

  const different = (similarity: number): Comparison => ({
    verdict: 'different',
    similarity: round(similarity),
    markers,
    kind: digest.kind,
  });
  if (status < 200 || status >= 300) return different(0);
  if (digest.kind !== original.kind) return different(0);
  let similarity: number;
  let similar: boolean;
  if (digest.kind === 'json') {
    const keys = jaccard(original.keyPaths ?? [], digest.keyPaths ?? []);
    const leaves = jaccard(original.leaves ?? [], digest.leaves ?? []);
    similarity = Math.min(keys, leaves);
    similar = keys >= threshold && leaves >= threshold;
  } else if (digest.kind === 'html') {
    similarity = jaccard(original.words ?? [], digest.words ?? []);
    similar = similarity >= threshold;
  } else {
    const a = original.length;
    const b = replay.length;
    similarity = a === 0 && b === 0 ? 1 : Math.min(a, b) / Math.max(a, b);
    similar = Math.abs(a - b) <= 0.1 * a;
  }
  if (!similar) return different(similarity);
  return { verdict: 'similar', similarity: round(similarity), markers, kind: digest.kind };
}
