// The baseline state in the finding details for every classification (09-REQ-20, 09-AC-07):
// golden HTML of the details block per state. UPDATE_GOLDEN=1 rewrites the files.
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, test } from 'vitest';
import { context } from '../../../src/html/context.ts';
import { findingDetails } from '../../../src/html/findings.ts';
import { STATES, statesInput } from '../../browser/fixtures.ts';

const GOLDEN = join(import.meta.dirname, '../../golden/html');

/** The block with a line break before each part, so a diff is readable. */
function pretty(markup: string): string {
  return `${markup.replace(/<div class="(ds|bs|kh)/gu, '\n<div class="$1')}\n`;
}

/** Visible text of markup, for the assertions on the state. */
const text = (markup: string): string =>
  markup
    .replace(/<[^>]+>/gu, ' ')
    .replace(/\s+/gu, ' ')
    .replace(/ ([:.;,])/gu, '$1')
    .replaceAll('&quot;', '"');

const EXPECTED: Record<(typeof STATES)[number], string[]> = {
  'new-blocking': [
    'New, blocking: not in the baseline',
    'severity ≥ medium and confidence ≥ medium fail the run',
    'Accept',
  ],
  'new-non-blocking': ['New, not blocking: not in the baseline; below the gate', 'Accept'],
  accepted: [
    'In the baseline as accepted',
    'HSTS is set by the CDN, SEC-12',
    '2026-10-01',
    '2027-06-30',
  ],
  'accepted-expiring': ['In the baseline as accepted', 'Expires in 7 days (until 2026-12-01)'],
  wontfix: [
    'In the baseline as wontfix',
    'Note none',
    'no end date',
    'No note: baseline.requireNote expects a reason',
  ],
  'false-positive': ['In the baseline as false-positive', 'UI theme cookie, read by JavaScript'],
  expired: [
    'Expired: the baseline entry ended on 2026-11-20',
    'until the cart rewrite, SEC-7',
    'Accept',
  ],
};

describe('09-AC-07 baseline state in the finding details (09-REQ-20)', () => {
  const input = statesInput();
  const ctx = context(input);
  test.each(STATES.map((s, i) => [s, i] as const))(
    '09-AC-07 %s: the details show the right baseline state (golden file)',
    (state, i) => {
      const finding = input.report.findings[i];
      if (finding === undefined) throw new Error('fixture');
      const markup = pretty(findingDetails(ctx, finding).text);
      for (const part of EXPECTED[state]) expect(text(markup), part).toContain(part);
      if (state !== 'new-blocking' && state !== 'new-non-blocking' && state !== 'expired') {
        expect(text(markup)).not.toContain('Accept add to');
      }
      const file = join(GOLDEN, `details-${state}.html`);
      if (process.env.UPDATE_GOLDEN === '1' || !existsSync(file)) writeFileSync(file, markup);
      expect(markup).toBe(readFileSync(file, 'utf8'));
    },
  );
});
