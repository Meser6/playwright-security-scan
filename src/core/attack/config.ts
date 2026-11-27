// Options of the attack mode with ZAP (19, chapter 4) and the checks that run before any test
// (19-REQ-02, 19-REQ-05, 17-REQ-14, 19 chapter 11a). Pure: the platform and the roles come in.
import { productionPattern } from '../authz/config.ts';
import type { ConfigIssue } from '../config/types.ts';
import { canonicalOrigin } from '../normalize/index.ts';
import type { AttackSummary, Confidence, Severity } from '../types/index.ts';

export const ATTACK_METHODS = ['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'] as const;
export type AttackMethod = (typeof ATTACK_METHODS)[number];
/** Methods that change data (14-REQ-05): a warning in the banner and the report. */
export const MUTATING_METHODS: readonly AttackMethod[] = ['POST', 'PUT', 'PATCH', 'DELETE'];
export const ATTACK_LEVELS = ['low', 'medium', 'high'] as const;
export type AttackLevel = (typeof ATTACK_LEVELS)[number];

export interface AttackInput {
  engine?: 'zap';
  allowedOrigins?: string[];
  denyOrigins?: string[];
  iUnderstandThisIsNotProduction?: boolean;
  /** Address of a running ZAP; without it the package starts a container (19-REQ-04). */
  zapUrl?: string;
  image?: string;
  /** Role the scan runs in (18-REQ-07); the first role or anonymous by default. */
  role?: string;
  methods?: AttackMethod[];
  strength?: AttackLevel;
  threshold?: AttackLevel;
  maxDurationMinutes?: number;
  maxRequests?: number;
  maxRps?: number;
  exclude?: string[];
  probeHeader?: boolean;
}

export interface ResolvedAttack {
  engine: 'zap';
  allowedOrigins: string[];
  denyOrigins: string[];
  iUnderstandThisIsNotProduction: boolean;
  zapUrl: string | null;
  image: string;
  role: string | null;
  methods: AttackMethod[];
  strength: AttackLevel;
  threshold: AttackLevel;
  maxDurationMinutes: number;
  maxRequests: number;
  maxRps: number;
  exclude: string[];
  probeHeader: boolean;
  /** rules['zap.<id>'] of the config (19-REQ-09): off, or severity/confidence over the alert's. */
  rules: Record<string, { enabled: boolean; severity?: Severity; confidence?: Confidence }>;
}

/** Defaults of 19, chapter 4. `allowedOrigins` has none on purpose (R-05). */
export const ATTACK_DEFAULTS: ResolvedAttack = {
  engine: 'zap',
  allowedOrigins: [],
  denyOrigins: [],
  iUnderstandThisIsNotProduction: false,
  zapUrl: null,
  image: 'zaproxy/zap-stable',
  role: null,
  methods: ['GET', 'HEAD', 'OPTIONS'],
  strength: 'medium',
  threshold: 'medium',
  maxDurationMinutes: 30,
  maxRequests: 2000,
  maxRps: 10,
  exclude: [],
  probeHeader: true,
  rules: {},
};

export function resolveAttack(input: AttackInput | undefined): ResolvedAttack {
  const i = input ?? {};
  const canonical = (list: readonly string[] | undefined): string[] =>
    (list ?? []).map((o) => canonicalOrigin(o) ?? o);
  return {
    ...ATTACK_DEFAULTS,
    ...i,
    allowedOrigins: canonical(i.allowedOrigins),
    denyOrigins: canonical(i.denyOrigins),
    zapUrl: i.zapUrl === undefined ? null : i.zapUrl.replace(/\/+$/, ''),
    role: i.role ?? null,
    methods: [...new Set(i.methods ?? ATTACK_DEFAULTS.methods)],
    exclude: [...(i.exclude ?? [])],
    rules: {},
  };
}

/** Why an origin may not get a request of ZAP (19-REQ-02, 18-REQ-03), or null when it may. */
export function attackDeniedReason(origin: string, attack: ResolvedAttack): string | null {
  if (attack.denyOrigins.includes(origin)) return 'attack.denyOrigins';
  if (attack.iUnderstandThisIsNotProduction) return null;
  const pattern = productionPattern(origin);
  return pattern === null ? null : `the built-in production pattern "${pattern}"`;
}

/** Whether ZAP may get a request to `origin` (18-REQ-04): allowed and not denied. */
export function attackOriginAllowed(origin: string | null, attack: ResolvedAttack): boolean {
  return (
    origin !== null &&
    attack.allowedOrigins.includes(origin) &&
    attackDeniedReason(origin, attack) === null
  );
}

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

/** A local origin (05-REQ-06): a container outside Linux cannot reach it (19-REQ-05). */
export function isLocalOrigin(origin: string): boolean {
  try {
    const host = new URL(origin).hostname.toLowerCase();
    return LOCAL_HOSTS.has(host) || host.endsWith('.localhost');
  } catch {
    return false;
  }
}

export interface AttackModeContext {
  /** process.platform. */
  platform: string;
  /** --shard on the command line or in the Playwright config (17-REQ-14). */
  sharded: boolean;
  /** Role names of the run (18-REQ-07), for attack.role. */
  roles: readonly string[];
}

/**
 * Configuration errors of an attack run, before any test (19-REQ-02, 19-REQ-05, 17-REQ-14,
 * ATTACK_ROLE_UNKNOWN of 19 chapter 11a). Empty when the run may start.
 */
export function attackModeIssues(attack: ResolvedAttack, ctx: AttackModeContext): ConfigIssue[] {
  const issues: ConfigIssue[] = [];
  if (ctx.sharded) {
    issues.push({
      code: 'ATTACK_SHARDED',
      path: '--shard',
      message:
        'the attack mode does not run in shards: ZAP scans the traffic of all tests at once on one machine',
      hint: 'Run the attack as one job without --shard (a nightly job, docs/attack.md); shard the scan and baseline runs only.',
    });
  }
  if (attack.allowedOrigins.length === 0) {
    issues.push({
      code: 'ATTACK_ORIGINS_REQUIRED',
      path: 'attack.allowedOrigins',
      message: 'attack.allowedOrigins: the attack mode needs the origins ZAP may attack',
      hint: 'List them, e.g. attack: { allowedOrigins: ["https://staging.example.com"] }. There is no default on purpose (docs/attack.md).',
    });
    return issues;
  }
  attack.allowedOrigins.forEach((origin, i) => {
    const reason = attackDeniedReason(origin, attack);
    if (reason !== null) {
      issues.push({
        code: 'ATTACK_ORIGIN_DENIED',
        path: `attack.allowedOrigins[${i}]`,
        message: `attack.allowedOrigins[${i}]: ${origin} matches ${reason}; the package never attacks production`,
        hint:
          reason === 'attack.denyOrigins'
            ? 'Remove it from attack.allowedOrigins: attack.denyOrigins always wins.'
            : 'Use a test environment. If this origin is not production, set attack.iUnderstandThisIsNotProduction: true.',
      });
    }
  });
  if (attack.zapUrl === null && ctx.platform !== 'linux') {
    const local = attack.allowedOrigins.filter(isLocalOrigin);
    if (local.length > 0) {
      issues.push({
        code: 'ATTACK_LOCAL_ORIGIN_UNSUPPORTED',
        path: 'attack.allowedOrigins',
        message: `attack.allowedOrigins: ${local.join(', ')} is local, and a ZAP container on ${ctx.platform} cannot reach the localhost of this machine`,
        hint: 'Run the attack in CI on Linux (Docker uses --network host there), or start ZAP yourself and set attack.zapUrl.',
      });
    }
  }
  if (attack.role !== null && attack.role !== 'anonymous' && !ctx.roles.includes(attack.role)) {
    issues.push({
      code: 'ATTACK_ROLE_UNKNOWN',
      path: 'attack.role',
      message: `attack.role: ${JSON.stringify(attack.role)} is not a role of this run`,
      hint: `Roles are projects with a storageState path (or authz.roles.<project>.role): ${ctx.roles.length === 0 ? 'none here' : ctx.roles.join(', ')}; or use "anonymous".`,
    });
  }
  return issues;
}

/** The role of the scan (19 chapter 11a): attack.role, else the first role, else anonymous. */
export function attackRole(attack: ResolvedAttack, roles: readonly string[]): string {
  return attack.role ?? roles[0] ?? 'anonymous';
}

/** The summary of an attack before (or without) the scan (19-REQ-10). */
export function emptyAttackSummary(attack: ResolvedAttack, role: string): AttackSummary {
  return {
    engine: 'zap',
    zap: attack.zapUrl === null ? 'docker' : 'url',
    zapVersion: null,
    role,
    origins: [...attack.allowedOrigins],
    methods: [...attack.methods],
    durationSeconds: 0,
    requests: 0,
    templates: { sent: 0, failed: 0 },
    alerts: { mapped: 0, falsePositive: 0, passive: 0, off: 0 },
    budget: {
      maxRequests: attack.maxRequests,
      maxDurationMinutes: attack.maxDurationMinutes,
      maxRps: attack.maxRps,
    },
    budgetExceeded: false,
    completed: false,
    rules: [],
  };
}

/** The Attack row of the start banner (19-REQ-01, 19 chapter 11a). */
export function attackBannerText(attack: ResolvedAttack, role: string): string {
  return [
    attack.zapUrl === null ? `ZAP docker ${attack.image}` : `ZAP at ${attack.zapUrl}`,
    `origins ${attack.allowedOrigins.join(', ')}`,
    `role ${role}`,
    `budget ${String(attack.maxDurationMinutes)} min, ${String(attack.maxRequests)} requests, ${String(attack.maxRps)} rps`,
  ].join(' · ');
}
