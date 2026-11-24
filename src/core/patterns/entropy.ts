// Shannon entropy of a text, in bits per character (06, chapter 4.2: token-like values).

/** Bits per character of `text`; 0 for an empty text. */
export function entropy(text: string): number {
  if (text.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of text) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  const length = [...text].length;
  let bits = 0;
  for (const count of counts.values()) {
    const p = count / length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

/** Minimum length of a token-like value (06, chapter 4.2). */
export const TOKEN_MIN_LENGTH = 16;
/** Minimum entropy of a token-like value, bits per character (06, chapter 4.2). */
export const TOKEN_MIN_ENTROPY = 3.5;

const JWT = /^eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*$/;

/** A JWT shape: three base64url segments, the first one starting a JSON object. */
export function looksLikeJwt(value: string): boolean {
  return JWT.test(value);
}

/** A JWT, or at least 16 characters with entropy of at least 3.5 bits per character. */
export function looksLikeToken(value: string): boolean {
  if (looksLikeJwt(value)) return true;
  return value.length >= TOKEN_MIN_LENGTH && entropy(value) >= TOKEN_MIN_ENTROPY;
}
