// Types of core (02). File formats are generated from schemas/; the in-memory types of the
// worker (records, browser events, raw findings) are declared here.
import type {
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
  TestAttachment,
  TestContextRef,
} from './generated/formats.ts';

export type {
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
  | { kind: 'cookie-jar'; cookies: CookieView[]; context: TestContextRef };

export type BrowserEventKind = BrowserEvent['kind'];

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
