// Content-Security-Policy parsing (06, chapter 4.1).

/** One policy: directive name (lowercase) → source list (lowercase except nonce/hash values). */
export type Policy = Map<string, string[]>;

/** Policies of a header value; several policies may be comma-separated. */
export function parseCsp(value: string): Policy[] {
  return value
    .split(',')
    .map((policy) => {
      const map: Policy = new Map();
      for (const part of policy.split(';')) {
        const tokens = part.trim().split(/\s+/).filter(Boolean);
        const [name, ...sources] = tokens;
        if (name === undefined) continue;
        const key = name.toLowerCase();
        // The first occurrence of a directive wins (CSP3, 2.2.1).
        if (!map.has(key))
          map.set(
            key,
            sources.map((s) => (/^'(nonce|sha\d+)-/i.test(s) ? s : s.toLowerCase())),
          );
      }
      return map;
    })
    .filter((p) => p.size > 0);
}

/** Policies of every header with this name. */
export function policies(values: readonly string[]): Policy[] {
  return values.flatMap(parseCsp);
}

/** The sources that govern scripts: script-src, else default-src; undefined when neither. */
export function scriptSources(policy: Policy): string[] | undefined {
  return policy.get('script-src') ?? policy.get('default-src');
}

/** CSP `<meta http-equiv>` in the first 4 KB of an HTML body (06, chapter 4.1). */
export function metaCsp(html: string | undefined): string[] {
  if (html === undefined) return [];
  const head = html.slice(0, 4096);
  const out: string[] = [];
  const re = /<meta\s[^>]*http-equiv\s*=\s*["']?content-security-policy["']?[^>]*>/gi;
  for (const tag of head.match(re) ?? []) {
    const content = /content\s*=\s*("([^"]*)"|'([^']*)')/i.exec(tag);
    const value = content?.[2] ?? content?.[3];
    if (value !== undefined) out.push(value);
  }
  return out;
}

/** Unsafe script sources of one policy (06, chapter 4.1: header.csp-unsafe). */
export function unsafeScriptTokens(policy: Policy): string[] {
  const sources = scriptSources(policy);
  if (sources === undefined) return [];
  const hasNonceOrHash = sources.some((s) => /^'(nonce|sha256|sha384|sha512)-/i.test(s));
  const strictDynamic = sources.includes("'strict-dynamic'");
  const out: string[] = [];
  for (const s of sources) {
    if (s === "'unsafe-inline'" && !hasNonceOrHash) out.push(s);
    else if (s === "'unsafe-eval'") out.push(s);
    else if (!strictDynamic && (s === '*' || s === 'http:' || s === 'https:' || s === 'data:'))
      out.push(s);
  }
  return [...new Set(out)];
}
