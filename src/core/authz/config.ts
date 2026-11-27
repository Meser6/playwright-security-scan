// Options of the authorization tests (18-REQ-01) and the safety checks that run before any test
// (18-REQ-02, 18-REQ-03). Pure: the production block list and the exclude patterns are data.
import { canonicalOrigin } from '../normalize/index.ts';

/** Per-project role options (18-REQ-07). */
export interface RoleOptions {
  /** A shared role name for two projects with different users of one role (horizontal test). */
  role?: string;
  /** Permission level for the vertical test; higher = more permissions. */
  level?: number;
  /** Credential headers of the role, e.g. authorization for token-based apps. */
  headers?: Record<string, string>;
  /** The project is not a role. */
  skip?: boolean;
}

export interface AuthzInput {
  enabled?: boolean;
  allowedOrigins?: string[];
  denyOrigins?: string[];
  iUnderstandThisIsNotProduction?: boolean;
  roles?: Record<string, RoleOptions>;
  exclude?: string[];
  maxRequests?: number;
  maxRps?: number;
  maxDurationMinutes?: number;
  similarity?: number;
  probeHeader?: boolean;
  tests?: { unauthenticated?: boolean; horizontal?: boolean; vertical?: boolean };
}

export interface ResolvedAuthz {
  enabled: boolean;
  allowedOrigins: string[];
  denyOrigins: string[];
  iUnderstandThisIsNotProduction: boolean;
  roles: Record<string, RoleOptions>;
  exclude: string[];
  maxRequests: number;
  maxRps: number;
  maxDurationMinutes: number;
  similarity: number;
  probeHeader: boolean;
  tests: { unauthenticated: boolean; horizontal: boolean; vertical: boolean };
}

/** Defaults of 18-REQ-01 (18-D-05). `allowedOrigins` has none on purpose (R-05). */
export const AUTHZ_DEFAULTS: ResolvedAuthz = {
  enabled: false,
  allowedOrigins: [],
  denyOrigins: [],
  iUnderstandThisIsNotProduction: false,
  roles: {},
  exclude: [],
  maxRequests: 500,
  maxRps: 5,
  maxDurationMinutes: 10,
  similarity: 0.8,
  probeHeader: true,
  tests: { unauthenticated: true, horizontal: true, vertical: true },
};

export function resolveAuthz(input: AuthzInput | undefined): ResolvedAuthz {
  const i = input ?? {};
  const canonical = (list: readonly string[] | undefined): string[] =>
    (list ?? []).map((o) => canonicalOrigin(o) ?? o);
  return {
    ...AUTHZ_DEFAULTS,
    ...i,
    allowedOrigins: canonical(i.allowedOrigins),
    denyOrigins: canonical(i.denyOrigins),
    roles: { ...(i.roles ?? {}) },
    exclude: [...(i.exclude ?? [])],
    tests: { ...AUTHZ_DEFAULTS.tests, ...(i.tests ?? {}) },
  };
}

const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;

/**
 * The built-in production pattern an origin matches (18-REQ-03), or null: a host starting with
 * `www.`, a `prod`/`production` label part (split on `.` and `-`), or a domain without a subdomain
 * (two labels). localhost, *.localhost and IP addresses never match.
 */
export function productionPattern(origin: string): string | null {
  let host: string;
  try {
    host = new URL(origin).hostname.toLowerCase();
  } catch {
    return null;
  }
  if (host === 'localhost' || host.endsWith('.localhost')) return null;
  if (IPV4.test(host) || host.startsWith('[')) return null;
  if (host.startsWith('www.')) return 'www.*';
  const parts = host.split(/[.-]/);
  if (parts.includes('prod')) return '*prod*';
  if (parts.includes('production')) return '*production*';
  if (host.split('.').length <= 2) return 'domain without a subdomain';
  return null;
}

/** Why an origin may not get a request of the package (18-REQ-03), or null when it may. */
export function deniedReason(origin: string, authz: ResolvedAuthz): string | null {
  if (authz.denyOrigins.includes(origin)) return 'authz.denyOrigins';
  if (authz.iUnderstandThisIsNotProduction) return null;
  const pattern = productionPattern(origin);
  return pattern === null ? null : `the built-in production pattern "${pattern}"`;
}

/** Path segments of the built-in logout list (18-REQ-10). */
const LOGOUT = /^(?:logout|log-out|signout|sign-out)$/i;

/** Whether a URL path is a logout endpoint (18-REQ-10). */
export function isLogoutPath(path: string): boolean {
  return path.split('/').some((segment) => LOGOUT.test(segment));
}

const METHOD_PREFIX = /^[A-Z]+ /;

/**
 * Matcher of authz.exclude (18 chapter 12a): `*` is any text within a path segment; a pattern
 * without a leading method matches every method.
 */
export function excludeMatcher(patterns: readonly string[]): (key: string) => boolean {
  const compiled = patterns.map((pattern) => {
    const withMethod = METHOD_PREFIX.test(pattern);
    const source = pattern
      .split('*')
      .map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
      .join('[^/]*');
    return { withMethod, re: new RegExp(`^${source}$`) };
  });
  return (key) => {
    const withoutMethod = key.replace(METHOD_PREFIX, '');
    return compiled.some((c) => c.re.test(c.withMethod ? key : withoutMethod));
  };
}
