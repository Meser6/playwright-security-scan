// The baseline run writes the file (08, chapter 6) deterministically (02-REQ-01).
import type { BaselineEntry, BaselineFile, EntryRef, Finding } from '../types/index.ts';

export interface BaselineDiff {
  added: { fingerprint: string; ruleId: string; subject: string; severity: string }[];
  removed: EntryRef[];
  unchanged: number;
}

/**
 * The new baseline (08-REQ-08): existing entries keep status, note, until and addedAt; their
 * severity follows the current finding; new findings are added as accepted with addedAt = today;
 * resolved entries are removed when `prune` (not in a partial run, never false positives,
 * 08-REQ-07).
 */
export function updateBaseline(
  existing: BaselineFile | undefined,
  findings: readonly Finding[],
  resolved: readonly EntryRef[],
  options: { today: string; generatedBy: string; prune: boolean },
): { file: BaselineFile; diff: BaselineDiff } {
  const entries: Record<string, BaselineEntry> = {};
  for (const [print, entry] of Object.entries(existing?.findings ?? {}))
    entries[print] = { ...entry };
  const added: BaselineDiff['added'] = [];
  for (const f of findings) {
    const current = entries[f.fingerprint];
    if (current === undefined) {
      entries[f.fingerprint] = {
        ruleId: f.ruleId,
        subject: f.subject,
        severity: f.severity,
        status: 'accepted',
        addedAt: options.today,
      };
      added.push({
        fingerprint: f.fingerprint,
        ruleId: f.ruleId,
        subject: f.subject,
        severity: f.severity,
      });
    } else {
      current.severity = f.severity;
    }
  }
  const removed: EntryRef[] = [];
  if (options.prune) {
    for (const ref of resolved) {
      const entry = entries[ref.fingerprint];
      if (entry === undefined || entry.status === 'false-positive') continue;
      Reflect.deleteProperty(entries, ref.fingerprint);
      removed.push(ref);
    }
  }
  const total = Object.keys(entries).length;
  return {
    file: { schemaVersion: 1, generatedBy: options.generatedBy, findings: entries },
    diff: {
      added: added.sort((a, b) => (a.fingerprint < b.fingerprint ? -1 : 1)),
      removed,
      unchanged: total - added.length,
    },
  };
}

/** Field order of an entry in the file. */
const ORDER: (keyof BaselineEntry)[] = [
  'ruleId',
  'subject',
  'severity',
  'status',
  'note',
  'until',
  'addedAt',
];

/** File text: keys sorted, 2-space indent, trailing newline (02-REQ-01). */
export function serializeBaseline(file: BaselineFile): string {
  const findings: Record<string, Record<string, unknown>> = {};
  for (const print of Object.keys(file.findings).sort()) {
    const entry = file.findings[print] as BaselineEntry;
    const ordered: Record<string, unknown> = {};
    for (const key of ORDER) if (entry[key] !== undefined) ordered[key] = entry[key];
    findings[print] = ordered;
  }
  const doc: Record<string, unknown> = { schemaVersion: 1 };
  if (file.generatedBy !== undefined) doc.generatedBy = file.generatedBy;
  doc.findings = findings;
  return `${JSON.stringify(doc, null, 2)}\n`;
}
