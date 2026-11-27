// Roles and the replay plan of the authorization tests (18-REQ-07, 18-REQ-14). Pure: the reporter
// passes the projects of the Playwright config, the templates of the run and the observed map.
import type { ResolvedSecurityConfig } from '../config/index.ts';
import { compareTests } from '../fingerprint/index.ts';
import { ID_PATTERNS } from '../normalize/patterns.ts';
import type { Coverage } from '../types/index.ts';
import type { ResolvedAuthz, RoleOptions } from './config.ts';
import { AUTHZ_RULE_OF } from './manifest.ts';
import type { AuthzTest } from './manifest.ts';
import type { ReplayResult, RequestTemplate, RoleInfo, SkipReason } from './types.ts';

export const ANONYMOUS = 'anonymous';

export interface ProjectInfo {
  name: string;
  /** use.storageState when it is a path (18-REQ-07). */
  storageState: string | undefined;
  /** The collector runs in it (scope.projects). */
  scanned: boolean;
}

/** A role with the projects (users) behind it. */
export interface Role extends RoleInfo {
  /** RoleOptions.headers of the first project; values never leave the reporter. */
  headers: Record<string, string>;
}

/** Role name of a project: authz.roles.<project>.role or the project name. */
export function roleNameOf(project: string, roles: Record<string, RoleOptions>): string {
  return roles[project]?.role ?? project;
}

/** Roles of the run (18-REQ-07), in the order of the projects in the config. */
export function rolesOf(projects: readonly ProjectInfo[], authz: ResolvedAuthz): Role[] {
  const out = new Map<string, Role>();
  for (const project of projects) {
    const options = authz.roles[project.name] ?? {};
    if (project.storageState === undefined || !project.scanned || options.skip === true) continue;
    const name = roleNameOf(project.name, authz.roles);
    const role = out.get(name);
    if (role === undefined) {
      out.set(name, {
        name,
        projects: [project.name],
        level: options.level ?? null,
        headers: { ...(options.headers ?? {}) },
      });
    } else {
      role.projects.push(project.name);
      if (role.level === null && options.level !== undefined) role.level = options.level;
    }
  }
  return [...out.values()];
}

/** A replay to send, or a row decided without a request (`public`, `skipped`). */
export interface PlannedReplay {
  test: AuthzTest;
  template: RequestTemplate;
  fromRole: string;
  asRole: string;
  asProject: string | null;
  decided?: { result: 'public' | 'skipped'; reason?: SkipReason };
}

export interface Plan {
  replays: PlannedReplay[];
  /** Templates after the deduplication of 18-REQ-14. */
  templates: number;
  /** Missing role pairs (18-REQ-09). */
  notes: string[];
}

/** Whether a template points at an object: an id in the key or an id-like query value (18-REQ-14). */
export function hasObjectId(template: Pick<RequestTemplate, 'endpointKey' | 'url'>): boolean {
  if (/\/:(?:id|email)(?:[/?]|$)/.test(template.endpointKey)) return true;
  let params: URLSearchParams;
  try {
    params = new URL(template.url).searchParams;
  } catch {
    return false;
  }
  for (const value of params.values()) {
    if (
      ID_PATTERNS.number.test(value) ||
      ID_PATTERNS.uuid.test(value) ||
      ID_PATTERNS.hex.test(value)
    )
      return true;
  }
  return false;
}

/** The first template per (endpoint key, project) in the test order (18-REQ-14). */
export function dedupeTemplates(templates: readonly RequestTemplate[]): RequestTemplate[] {
  const sorted = [...templates].sort(
    (a, b) => compareTests(a.context, b.context) || (a.endpointKey < b.endpointKey ? -1 : 1),
  );
  const seen = new Set<string>();
  const out: RequestTemplate[] = [];
  for (const t of sorted) {
    const id = `${t.endpointKey}\u0000${t.project}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(t);
  }
  return out.sort((a, b) =>
    a.endpointKey === b.endpointKey
      ? compareTests(a.context, b.context)
      : a.endpointKey < b.endpointKey
        ? -1
        : 1,
  );
}

const ruleOn = (config: ResolvedSecurityConfig, test: AuthzTest): boolean =>
  config.authz.tests[test] && config.rules[AUTHZ_RULE_OF[test]]?.enabled !== false;

const hasAuthorizationHeader = (role: Role): boolean =>
  Object.keys(role.headers).some((name) => name.toLowerCase() === 'authorization');

/**
 * The replays of a run (18-REQ-14): without a session first, then horizontal, then vertical; by
 * endpoint key within each test.
 */
export function planReplays(
  templates: readonly RequestTemplate[],
  roles: readonly Role[],
  observed: NonNullable<Coverage['authzObserved']>,
  config: ResolvedSecurityConfig,
): Plan {
  const list = dedupeTemplates(templates);
  const byName = new Map(roles.map((r) => [r.name, r]));
  const roleOfProject = new Map<string, Role>();
  for (const r of roles) for (const p of r.projects) roleOfProject.set(p, r);
  const replays: PlannedReplay[] = [];
  const notes = new Set<string>();
  const credentials = (t: RequestTemplate, as: Role): PlannedReplay['decided'] =>
    t.hadAuthorization && !hasAuthorizationHeader(as)
      ? { result: 'skipped', reason: 'no-credentials' }
      : undefined;

  if (ruleOn(config, 'unauthenticated')) {
    for (const t of list) {
      if (!t.withCredentials) continue;
      const fromRole = roleOfProject.get(t.project)?.name ?? t.project;
      const replay: PlannedReplay = {
        test: 'unauthenticated',
        template: t,
        fromRole,
        asRole: ANONYMOUS,
        asProject: null,
      };
      if (observed[t.endpointKey]?.public === true) replay.decided = { result: 'public' };
      replays.push(replay);
    }
  }
  if (ruleOn(config, 'horizontal')) {
    for (const t of list) {
      const role = roleOfProject.get(t.project);
      if (role === undefined || !t.withCredentials || !hasObjectId(t)) continue;
      const others = role.projects.filter((p) => p !== t.project);
      if (others.length === 0) {
        notes.add('horizontal: needs two users of one role');
        continue;
      }
      for (const as of others) {
        const replay: PlannedReplay = {
          test: 'horizontal',
          template: t,
          fromRole: role.name,
          asRole: role.name,
          asProject: as,
        };
        if (observed[t.endpointKey]?.public === true) replay.decided = { result: 'public' };
        else {
          const decided = credentials(t, role);
          if (decided !== undefined) replay.decided = decided;
        }
        replays.push(replay);
      }
    }
  }
  if (ruleOn(config, 'vertical')) {
    for (const t of list) {
      const role = roleOfProject.get(t.project);
      if (role?.level === null || role === undefined || !t.withCredentials) continue;
      const level = role.level;
      const seenBy = new Set(observed[t.endpointKey]?.roles ?? []);
      for (const lower of roles) {
        if (lower.level === null || lower.level >= level || seenBy.has(lower.name)) continue;
        const target = byName.get(lower.name) as Role;
        const replay: PlannedReplay = {
          test: 'vertical',
          template: t,
          fromRole: role.name,
          asRole: target.name,
          asProject: target.projects[0] ?? null,
        };
        const decided = credentials(t, target);
        if (decided !== undefined) replay.decided = decided;
        replays.push(replay);
      }
    }
  }
  return { replays, templates: list.length, notes: [...notes].sort() };
}

/** The result row of a replay decided without a request. */
export function decidedResult(p: PlannedReplay): ReplayResult | undefined {
  if (p.decided === undefined) return undefined;
  return resultOf(
    p,
    p.decided.reason === undefined
      ? { result: p.decided.result }
      : { result: p.decided.result, reason: p.decided.reason },
  );
}

/** A result row for a planned replay. */
export function resultOf(
  p: PlannedReplay,
  outcome: Pick<ReplayResult, 'result'> & Partial<ReplayResult>,
): ReplayResult {
  return {
    test: p.test,
    endpointKey: p.template.endpointKey,
    origin: p.template.origin,
    fromRole: p.fromRole,
    fromProject: p.template.project,
    asRole: p.asRole,
    asProject: p.asProject,
    originalStatus: p.template.digest.status,
    kind: p.template.digest.kind,
    markers: false,
    source: p.template.source,
    context: p.template.context,
    ...outcome,
  };
}

const roleCount = (roles: readonly Role[]): string =>
  `${String(roles.length)} ${roles.length === 1 ? 'role' : 'roles'} + ${ANONYMOUS}`;

/** The Authz row of the start banner (04-REQ-06). */
export function authzBannerText(
  roles: readonly Role[],
  authz: ResolvedAuthz,
  offByEnv: boolean,
): string {
  if (offByEnv) return 'disabled by PW_SEC_AUTHZ=0';
  return `enabled · ${roleCount(roles)} · budget ${String(authz.maxRequests)} requests`;
}

/** Projects of the roles as the check lists them (18-REQ-19). */
export function roleList(roles: readonly Role[], authz: ResolvedAuthz): string {
  const items: string[] = [];
  for (const role of roles) {
    for (const project of role.projects) {
      const notes: string[] = [];
      const level = authz.roles[project]?.level;
      if (level !== undefined) notes.push(`level ${String(level)}`);
      if (role.name !== project) notes.push(`role ${role.name}`);
      items.push(notes.length === 0 ? project : `${project} (${notes.join(', ')})`);
    }
  }
  return [...items, ANONYMOUS].join(', ');
}

/** The Authz line of the check (18-REQ-19): nothing is sent. */
export function authzCheckText(
  roles: readonly Role[],
  authz: ResolvedAuthz,
  plan: Plan,
  offByEnv: boolean,
): string {
  if (offByEnv) return 'disabled by PW_SEC_AUTHZ=0';
  const planned = plan.replays.filter((p) => p.decided === undefined).length;
  return `enabled · roles: ${roleList(roles, authz)} · ${String(plan.templates)} ${plan.templates === 1 ? 'template' : 'templates'} · ~${String(planned)} replays planned (budget ${String(authz.maxRequests)})`;
}
