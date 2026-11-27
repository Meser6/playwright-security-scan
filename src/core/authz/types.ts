// Data of the authorization tests (02, chapter 2a; 18): request templates of the worker, raw replay
// results of the reporter (also in the shard file, 18-REQ-20).
import type { AttackTemplate } from '../attack/types.ts';
import type { Header, Source, TestContextRef } from '../types/index.ts';
import type { DigestKind, ResponseDigest } from './digest.ts';
import type { AuthzTest } from './manifest.ts';

/** A GET/HEAD request of a test that may be replayed (18-REQ-11), without credentials. */
export interface RequestTemplate {
  method: string;
  /** Full URL: only in the pw-sec-templates attachment, never in a report. */
  url: string;
  /** Allow-listed headers only (18-REQ-11). */
  headers: Header[];
  endpointKey: string;
  origin: string;
  project: string;
  source: Source;
  withCredentials: boolean;
  /** The original request carried an authorization header (18-REQ-08). */
  hadAuthorization: boolean;
  digest: ResponseDigest;
  context: TestContextRef;
}

/** The pw-sec-templates attachment (02-REQ-07). */
export interface TemplatesAttachment {
  schemaVersion: 1;
  templates: readonly RequestTemplate[];
  /** Templates of the attack mode (19 chapter 11a). */
  attack?: readonly AttackTemplate[];
}

export const TEMPLATES_ATTACHMENT = 'pw-sec-templates';
/** Maximum size of the templates attachment per test (18-REQ-13). */
export const MAX_TEMPLATES_BYTES = 512 * 1024;

/** Why a planned replay did not run (18 chapter 12a). */
export type SkipReason =
  | 'budget'
  | 'no-credentials'
  | 'state-missing'
  | 'interrupted'
  | 'origin-blocked'
  | 'replay-failed';

/** One planned or done replay: what the shard file keeps and the evaluation reads (18-REQ-20). */
export interface ReplayResult {
  test: AuthzTest;
  endpointKey: string;
  origin: string;
  /** Role and project of the original request. */
  fromRole: string;
  fromProject: string;
  /** Role (`anonymous` for no session) and project of the replay. */
  asRole: string;
  asProject: string | null;
  /** `public`: the key was seen without credentials (18-D-02), no request sent. */
  result: 'denied' | 'similar' | 'different' | 'skipped' | 'public';
  reason?: SkipReason;
  originalStatus: number;
  status?: number;
  similarity?: number;
  kind: DigestKind;
  markers: boolean;
  source: Source;
  context: TestContextRef;
}

/** A role of the run (18-REQ-07). */
export interface RoleInfo {
  name: string;
  projects: string[];
  level: number | null;
}

/** What the replays of a run (or a shard) produced (18-REQ-20). */
export interface AuthzRunData {
  roles: RoleInfo[];
  /** Templates after the deduplication of 18-REQ-14. */
  templates: number;
  budget: { maxRequests: number; used: number; exceeded: boolean };
  results: ReplayResult[];
  /** Missing role pairs, e.g. "horizontal: needs two users of one role". */
  notes: string[];
}
