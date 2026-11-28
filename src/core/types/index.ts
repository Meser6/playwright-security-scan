// Types of core (02). File formats are generated from schemas/; the in-memory types of the
// worker (records, browser events, raw findings) are declared here.
import type {
  AttackSummary,
  AuthzSummary,
  ClassifiedFinding,
  Coverage,
  Diagnostic,
  Entry as BaselineEntry,
  BaselineFile,
  EntryRef,
  Evidence,
  Finding,
  Location,
  OutcomeFile,
  RunReport,
  ShardInfo,
  TestAttachment,
  TestContextRef,
} from './generated/formats.ts';

export type {
  AttackSummary,
  AuthzSummary,
  BaselineEntry,
  BaselineFile,
  ClassifiedFinding,
  Coverage,
  Diagnostic,
  EntryRef,
  Evidence,
  Finding,
  Location,
  OutcomeFile,
  RunReport,
  ShardInfo,
  TestAttachment,
  TestContextRef,
};

export type Severity = Finding['severity'];
export type Confidence = Finding['confidence'];
export type FindingScope = Finding['scope'];
export type Source = Finding['sources'][number];
export type DiagnosticLevel = Diagnostic['level'];
export type Classification = ClassifiedFinding['classification'];
export type BaselineStatus = BaselineEntry['status'];

export const SEVERITIES: readonly Severity[] = ['info', 'low', 'medium', 'high', 'critical'];
export const CONFIDENCES: readonly Confidence[] = ['low', 'medium', 'high'];

/** Position of a severity in SEVERITIES; higher is more severe. */
export const severityRank = (s: Severity): number => SEVERITIES.indexOf(s);
/** Position of a confidence in CONFIDENCES; higher is surer. */
export const confidenceRank = (c: Confidence): number => CONFIDENCES.indexOf(c);

/** A header with a lowercase name (05-REQ-08). */
export interface Header {
  name: string;
  value: string;
}

/** A response body as rules see it (02, chapter 2). Never leaves the worker (P-07). */
export interface BodyView {
  /** From the content-type header, lowercase, without parameters. */
  contentType: string;
  /** Decoded as UTF-8, cut to limits.maxBodyBytes. */
  text: string;
  truncated: boolean;
  /** Of the whole body; analysis cache key (05-REQ-14), never in a report. */
  sha256: string;
}

/** One request/response pair, in the memory of the worker only (02, chapter 2). */
export interface ResponseRecord {
  /** Tells the rule inputs apart (02, chapter 2; 16-REQ-02). */
  kind: 'response';
  /** Sequence number within the test. */
  id: number;
  source: Source;
  /** Response from route.fulfill() (Q-05); browser source only. */
  mocked?: boolean;
  method: string;
  /** Raw URL; never written anywhere (P-07). */
  url: string;
  endpointKey: string;
  origin: string;
  /** request.resourceType(); 'api' for the api source. */
  resourceType: string;
  isNavigation: boolean;
  /** URL of the document of the frame that sent the request. */
  frameUrl?: string;
  requestHeaders: Header[];
  status: number;
  responseHeaders: Header[];
  redirectedFrom?: string;
  body?: BodyView;
  tls?: { protocol?: string };
  context: TestContextRef;
}

export interface CookieView {
  name: string;
  value: string;
  domain: string;
  path: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: 'Strict' | 'Lax' | 'None';
  /** Unix seconds; -1 for a session cookie. */
  expires: number;
  /** The in-scope origin whose host the cookie belongs to (set by the collector). */
  origin?: string;
}

/** An event from the browser, in the memory of the worker only (02, chapter 3). */
export type BrowserEvent =
  | {
      kind: 'csp-violation';
      documentOrigin: string;
      directive: string;
      blockedOrigin: string;
      disposition: 'enforce' | 'report';
      context: TestContextRef;
    }
  | {
      kind: 'storage';
      origin: string;
      area: 'local' | 'session';
      entries: { key: string; value: string }[];
      context: TestContextRef;
    }
  | {
      kind: 'cookie-jar';
      cookies: CookieView[];
      context: TestContextRef;
      /**
       * The SameSite the engine reports for a cookie without the attribute (05-REQ-23): Chromium
       * `Lax`, Firefox and WebKit `None`. A jar value equal to it is unknown. Missing = `Lax`.
       */
      missingSameSite?: 'Lax' | 'None';
    };

export type BrowserEventKind = BrowserEvent['kind'];

/**
 * What a cookie value looks like, without the value (06, chapter 4.14): `token` (a JWT or an opaque
 * token), `words` (plain words) or `other`. Enough for the session cookie heuristic of 06, 4.2.
 */
export type CookieValueClass = 'token' | 'words' | 'other';

/** One in-scope browser request of a test, without values (02, chapter 3). */
export interface TrafficRequest {
  /** Order of the response within the test. */
  id: number;
  method: string;
  endpointKey: string;
  origin: string;
  status: number;
  resourceType: string;
  /** POST to a login-like path with a 2xx or 3xx status (06, chapter 4.13.1). */
  isLoginCandidate: boolean;
  /** Content type of the request, lowercase, without parameters. */
  contentType?: string;
  /** Cookies of the cookie request header; the value only as a salted hash (07-REQ-15). */
  sentCookies: { name: string; valueHash: string; valueClass: CookieValueClass }[];
  /** Cookies of the Set-Cookie headers of the response, deletions left out. */
  setCookies: {
    name: string;
    valueHash: string;
    valueClass: CookieValueClass;
    domain?: string;
    /** As written; unset when the attribute is missing. */
    sameSite?: 'Strict' | 'Lax' | 'None';
    secure: boolean;
    httpOnly: boolean;
  }[];
  hasAuthorization: boolean;
  /** A CSRF header or form field, or x-requested-with (06, chapter 4.14). */
  csrfSignal: boolean;
}

/**
 * The end-of-test input of rules with `appliesTo.testEnd` (02, chapter 3; 06, chapter 4.13.1): the
 * in-scope browser traffic of one test in order, with cookie values only as hashes.
 */
export interface TestTraffic {
  kind: 'test-end';
  context: TestContextRef;
  requests: TrafficRequest[];
  jarCookies: Omit<CookieView, 'value'>[];
}

/** What a rule returns, before redaction and fingerprinting (02, chapter 4). */
export interface RawFinding {
  ruleId: string;
  severity: Severity;
  confidence: Confidence;
  scope: FindingScope;
  /** Origin, endpoint key, name@domain, storage key or normalized asset URL. */
  subject: string;
  /** Tells apart problems of one rule on one subject (07-REQ-06); never a value. */
  discriminator?: string;
  location: Location;
  evidence: Evidence[];
  message: string;
}
