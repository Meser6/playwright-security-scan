// Data of the attack mode (02, chapter 2a; 19 chapter 11a): request templates of the worker for ZAP
// and what the scan gives back to the end of the run.
import type { AttackSummary, Finding, Header, Source, TestContextRef } from '../types/index.ts';

/** A request of a test that ZAP gets with sendRequest (19-REQ-03), without credentials. */
export interface AttackTemplate {
  method: string;
  /** Full URL: only in the pw-sec-templates attachment, never in a report. */
  url: string;
  /** Allow-listed headers only (18-REQ-11). */
  headers: Header[];
  /** Request body of POST/PUT/PATCH/DELETE, redacted (19 chapter 11a). */
  body?: string;
  endpointKey: string;
  origin: string;
  project: string;
  source: Source;
  context: TestContextRef;
}

/** One alert as `alert/view/alert` of the ZAP API returns it (the fields the package reads). */
export interface ZapAlert {
  pluginId: string;
  name?: string;
  alert?: string;
  /** "High", "Medium", "Low", "Informational" (or the code 3…0). */
  risk: string;
  /** "Confirmed", "High", "Medium", "Low", "False Positive" (or the code 4…0). */
  confidence: string;
  method?: string;
  url: string;
  param?: string;
  evidence?: string;
  attack?: string;
  cweid?: string;
  tags?: Record<string, string>;
  description?: string;
  solution?: string;
}

/** What the attack gives to the end of the run (finishRun). */
export interface AttackRunData {
  summary: AttackSummary;
  /** Findings zap.<pluginId>, deduplicated by fingerprint. */
  findings: Finding[];
  /** Endpoint keys of the templates ZAP got (19-REQ-09: coverage of zap.* entries). */
  coveredKeys: string[];
}
