// Cookie domain matching for coverage (RFC 6265, 5.1.3), on canonical origins.

/** Whether the host of `origin` domain-matches the cookie `domain`. */
export function domainMatchesHost(origin: string, domain: string): boolean {
  let host: string;
  try {
    host = new URL(origin).hostname.toLowerCase();
  } catch {
    return false;
  }
  const d = domain.replace(/^\./, '').toLowerCase();
  return host === d || host.endsWith(`.${d}`);
}
