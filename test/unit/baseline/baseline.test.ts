import { describe, expect, test } from 'vitest';
import {
  classify,
  missingNotes,
  outcome,
  parseBaseline,
  resolveEntries,
  serializeBaseline,
  updateBaseline,
} from '../../../src/core/baseline/index.ts';
import type { Gate } from '../../../src/core/baseline/index.ts';
import { emptyCoverage } from '../../../src/core/coverage.ts';
import { RULE_IDS } from '../../../src/core/manifest/rules.ts';
import type { BaselineFile, Finding } from '../../../src/core/types/index.ts';

const gate: Gate = {
  minSeverity: 'medium',
  minConfidence: 'medium',
  failOnExpired: true,
  failOnNoTraffic: true,
};
const RULES = new Set(RULE_IDS);
const ref = { testId: 't', titlePath: ['t'], file: 'a.spec.ts', line: 1, project: 'p' };

function finding(
  ruleId: string,
  scope: Finding['scope'],
  subject: string,
  over: Partial<Finding> = {},
): Finding {
  return {
    ruleId,
    severity: 'medium',
    confidence: 'high',
    scope,
    subject,
    location: { origin: 'https://app.test' },
    evidence: [],
    message: 'm',
    fingerprint: `${ruleId}|${scope}|${subject}`,
    occurrences: 1,
    firstSeen: ref,
    tests: ['t'],
    sources: ['browser'],
    ...over,
  };
}

const cookie = finding('cookie.no-httponly', 'cookie', 'sid@app.test');
const hsts = finding('header.hsts-missing', 'origin', 'https://app.test', { severity: 'low' });
const file = (findings: BaselineFile['findings']): BaselineFile => ({ schemaVersion: 1, findings });

describe('classification (08, chapter 3)', () => {
  test('new findings block from the gate up; below the gate they do not (08-REQ-01)', () => {
    const [a, b] = classify([cookie, hsts], undefined, gate, '2026-11-24', true);
    expect([a?.classification, a?.blocking, b?.classification, b?.blocking]).toEqual([
      'new',
      true,
      'new',
      false,
    ]);
    const lowConfidence = classify(
      [{ ...cookie, confidence: 'low' }],
      undefined,
      gate,
      '2026-11-24',
      true,
    );
    expect(lowConfidence[0]?.blocking).toBe(false);
    expect(classify([cookie], undefined, gate, '2026-11-24', false)[0]?.blocking).toBe(false);
  });

  test('accepted, wontfix and false-positive entries never block (P-09)', () => {
    const base = file({
      [cookie.fingerprint]: {
        ruleId: cookie.ruleId,
        subject: cookie.subject,
        severity: 'medium',
        status: 'wontfix',
        note: 'n',
        addedAt: '2026-01-01',
      },
      [hsts.fingerprint]: {
        ruleId: hsts.ruleId,
        subject: hsts.subject,
        severity: 'low',
        status: 'false-positive',
        until: '2020-01-01',
        addedAt: '2026-01-01',
      },
    });
    const out = classify([cookie, hsts], base, gate, '2026-11-24', true);
    expect(out.map((f) => [f.classification, f.blocking])).toEqual([
      ['wontfix', false],
      ['false-positive', false],
    ]);
  });

  test('08-AC-02 an entry with until = yesterday and the finding still present gives code 2', () => {
    const base = file({
      [cookie.fingerprint]: {
        ruleId: cookie.ruleId,
        subject: cookie.subject,
        severity: 'medium',
        status: 'accepted',
        until: '2026-11-23',
        addedAt: '2026-01-01',
      },
    });
    const classified = classify([cookie], base, gate, '2026-11-24', true);
    expect(classified[0]).toMatchObject({ classification: 'expired', blocking: true });
    const result = outcome({
      findings: classified,
      resolved: 0,
      diagnostics: [],
      testsPassed: true,
      responses: 10,
      gate,
    });
    expect([result.code, result.name, result.expired]).toEqual([2, 'BASELINE_EXPIRED', 1]);
    const lenient = classify([cookie], base, { ...gate, failOnExpired: false }, '2026-11-24', true);
    expect(
      outcome({
        findings: lenient,
        resolved: 0,
        diagnostics: [],
        testsPassed: true,
        responses: 10,
        gate,
      }).code,
    ).toBe(0);
  });

  test('08-REQ-03 entries expiring within 14 days carry expiresInDays', () => {
    const base = file({
      [cookie.fingerprint]: {
        ruleId: cookie.ruleId,
        subject: cookie.subject,
        severity: 'medium',
        status: 'accepted',
        until: '2026-12-01',
        addedAt: '2026-01-01',
      },
    });
    expect(classify([cookie], base, gate, '2026-11-24', true)[0]?.baseline?.expiresInDays).toBe(7);
    expect(classify([cookie], base, gate, '2026-12-01', true)[0]).toMatchObject({
      classification: 'accepted',
      baseline: { expiresInDays: 0 },
    });
  });
});

describe('result codes (00, chapter 11; 08-REQ-02)', () => {
  const base = { resolved: 0, testsPassed: true, responses: 5, gate };
  test('TOOL_ERROR > NEW_FINDINGS > BASELINE_EXPIRED > NO_TRAFFIC > OK', () => {
    const newOne = classify([cookie], undefined, gate, '2026-11-24', true);
    const error = [{ code: 'BASELINE_INVALID', level: 'error' as const, message: 'x' }];
    expect(outcome({ ...base, findings: newOne, diagnostics: error }).name).toBe('TOOL_ERROR');
    expect(outcome({ ...base, findings: newOne, diagnostics: [] }).name).toBe('NEW_FINDINGS');
    expect(outcome({ ...base, findings: [], diagnostics: [], responses: 0 }).name).toBe(
      'NO_TRAFFIC',
    );
    expect(
      outcome({
        ...base,
        findings: [],
        diagnostics: [],
        responses: 0,
        gate: { ...gate, failOnNoTraffic: false },
      }).name,
    ).toBe('OK');
    expect(outcome({ ...base, findings: [], diagnostics: [] })).toEqual({
      schemaVersion: 2,
      code: 0,
      name: 'OK',
      testsPassed: true,
      newBlocking: 0,
      newNonBlocking: 0,
      expired: 0,
      resolved: 0,
    });
  });
});

describe('resolved and not covered entries (08, chapter 5)', () => {
  const entry = (f: Finding) => ({
    ruleId: f.ruleId,
    subject: f.subject,
    severity: f.severity,
    status: 'accepted' as const,
    addedAt: '2026-01-01',
  });
  const endpoint = finding('disclosure.stack-trace', 'endpoint', 'POST /api/orders');
  const asset = finding('data.secret-in-asset', 'asset', 'https://app.test/main.*.js');
  const storage = finding('data.token-in-storage', 'storage-key', 'token@https://app.test');
  const base = file(
    Object.fromEntries(
      [cookie, hsts, endpoint, asset, storage].map((f) => [f.fingerprint, entry(f)]),
    ),
  );

  test('08-REQ-05 an entry is resolved only when the run covered its scope', () => {
    const coverage = emptyCoverage();
    coverage.origins['https://app.test'] = { responses: 3, documents: 1 };
    coverage.endpoints['POST /api/orders'] = 1;
    coverage.assets.push('https://app.test/main.*.js');
    coverage.storageOrigins.push('https://app.test');
    const { resolved, notCovered } = resolveEntries(base, [], coverage, RULES);
    expect(resolved.map((r) => r.ruleId).sort()).toEqual([
      'cookie.no-httponly',
      'data.secret-in-asset',
      'data.token-in-storage',
      'disclosure.stack-trace',
      'header.hsts-missing',
    ]);
    expect(notCovered).toEqual([]);
  });

  test('08-AC-03 a partial run (e.g. --grep @smoke) leaves untouched endpoints not covered and keeps them', () => {
    const coverage = emptyCoverage();
    coverage.origins['https://app.test'] = { responses: 1, documents: 1 };
    coverage.endpoints['GET /'] = 1;
    const { resolved, notCovered } = resolveEntries(base, [], coverage, RULES);
    expect(notCovered.map((r) => r.ruleId).sort()).toEqual([
      'data.secret-in-asset',
      'data.token-in-storage',
      'disclosure.stack-trace',
    ]);
    const { file: next } = updateBaseline(base, [], resolved, {
      today: '2026-11-24',
      generatedBy: 'x',
      prune: true,
    });
    expect(Object.keys(next.findings).sort()).toEqual(
      [asset.fingerprint, endpoint.fingerprint, storage.fingerprint].sort(),
    );
  });

  test('04-AC-02 a filtered baseline run removes no entry at all', () => {
    const coverage = emptyCoverage();
    coverage.origins['https://app.test'] = { responses: 1, documents: 1 };
    const { resolved } = resolveEntries(base, [], coverage, RULES);
    expect(resolved.length).toBeGreaterThan(0);
    const { file: next, diff } = updateBaseline(base, [], resolved, {
      today: '2026-11-24',
      generatedBy: 'x',
      prune: false,
    });
    expect(Object.keys(next.findings)).toHaveLength(5);
    expect(diff.removed).toEqual([]);
  });

  test('entries of rules switched off are never resolved', () => {
    const coverage = emptyCoverage();
    coverage.origins['https://app.test'] = { responses: 1, documents: 1 };
    const { resolved } = resolveEntries(base, [], coverage, new Set(['cookie.no-httponly']));
    expect(resolved.map((r) => r.ruleId)).toEqual(['cookie.no-httponly']);
  });
});

describe('writing the baseline (08, chapter 6)', () => {
  test('08-REQ-08 keeps notes and dates, adds new findings, updates severity, prunes resolved', () => {
    const existing = file({
      [cookie.fingerprint]: {
        ruleId: cookie.ruleId,
        subject: cookie.subject,
        severity: 'low',
        status: 'accepted',
        note: 'SEC-1',
        until: '2027-01-01',
        addedAt: '2026-01-01',
      },
      'disclosure.stack-trace|endpoint|POST /x': {
        ruleId: 'disclosure.stack-trace',
        subject: 'POST /x',
        severity: 'medium',
        status: 'accepted',
        addedAt: '2026-01-01',
      },
      'header.csp-missing|origin|https://fp.test': {
        ruleId: 'header.csp-missing',
        subject: 'https://fp.test',
        severity: 'medium',
        status: 'false-positive',
        addedAt: '2026-01-01',
      },
    });
    const resolved = [
      {
        fingerprint: 'disclosure.stack-trace|endpoint|POST /x',
        ruleId: 'disclosure.stack-trace',
        subject: 'POST /x',
      },
      {
        fingerprint: 'header.csp-missing|origin|https://fp.test',
        ruleId: 'header.csp-missing',
        subject: 'https://fp.test',
      },
    ];
    const { file: next, diff } = updateBaseline(existing, [cookie, hsts], resolved, {
      today: '2026-11-24',
      generatedBy: 'playwright-security-scan@0.1.0',
      prune: true,
    });
    expect(next.findings[cookie.fingerprint]).toEqual({
      ruleId: cookie.ruleId,
      subject: cookie.subject,
      severity: 'medium',
      status: 'accepted',
      note: 'SEC-1',
      until: '2027-01-01',
      addedAt: '2026-01-01',
    });
    expect(next.findings[hsts.fingerprint]).toEqual({
      ruleId: hsts.ruleId,
      subject: hsts.subject,
      severity: 'low',
      status: 'accepted',
      addedAt: '2026-11-24',
    });
    expect(next.findings['header.csp-missing|origin|https://fp.test']?.status).toBe(
      'false-positive',
    );
    expect(diff).toEqual({
      added: [
        {
          fingerprint: hsts.fingerprint,
          ruleId: hsts.ruleId,
          subject: hsts.subject,
          severity: 'low',
        },
      ],
      removed: [resolved[0]],
      unchanged: 2,
    });
  });

  test('02-REQ-01 sorted keys, 2 spaces, trailing newline; the same input gives the same text', () => {
    const a = updateBaseline(undefined, [hsts, cookie], [], {
      today: '2026-11-24',
      generatedBy: 'g',
      prune: true,
    }).file;
    const b = updateBaseline(undefined, [cookie, hsts], [], {
      today: '2026-11-24',
      generatedBy: 'g',
      prune: true,
    }).file;
    const text = serializeBaseline(a);
    expect(text).toBe(serializeBaseline(b));
    expect(text.endsWith('}\n')).toBe(true);
    expect(text.indexOf(cookie.fingerprint)).toBeLessThan(text.indexOf(hsts.fingerprint));
    expect(text).toContain(
      '\n  "findings": {\n    "cookie.no-httponly|cookie|sid@app.test": {\n      "ruleId"',
    );
    const parsed = parseBaseline(text, 'b.json', RULES, RULES);
    expect(parsed.ok).toBe(true);
  });
});

describe('reading the baseline (08-REQ-11)', () => {
  const parse = (text: string) =>
    parseBaseline(
      text,
      'security-baseline.json',
      RULES,
      new Set([...RULES].filter((r) => r !== 'header.csp-missing')),
    );
  test('unreadable JSON, wrong version, unknown rule and invalid entries are errors with the place', () => {
    expect(parse('{').ok).toBe(false);
    const version = parse('{"schemaVersion":2,"findings":{}}');
    expect(version.diagnostics[0]?.message).toContain('schemaVersion must be 1');
    const unknown = parse(
      '{"schemaVersion":1,"findings":{"x|origin|a":{"ruleId":"cookie.no-htponly","subject":"a","severity":"low","status":"accepted","addedAt":"2026-01-01"}}}',
    );
    expect(unknown.diagnostics[0]).toMatchObject({ code: 'BASELINE_INVALID', level: 'error' });
    expect(unknown.diagnostics[0]?.message).toContain(
      'findings["x|origin|a"].ruleId: unknown rule "cookie.no-htponly"',
    );
    const wontfix = parse(
      '{"schemaVersion":1,"findings":{"x":{"ruleId":"cookie.no-httponly","subject":"a","severity":"low","status":"wontfix","addedAt":"2026-01-01"}}}',
    );
    expect(wontfix.diagnostics[0]?.message).toContain('needs a "note"');
  });

  test('rules switched off and until on false positives give diagnostics, not errors (08-REQ-04)', () => {
    const r = parse(
      '{"schemaVersion":1,"findings":{"a":{"ruleId":"header.csp-missing","subject":"a","severity":"low","status":"false-positive","until":"2027-01-01","addedAt":"2026-01-01"}}}',
    );
    expect(r.ok).toBe(true);
    expect(r.diagnostics.map((d) => [d.code, d.level])).toEqual([
      ['BASELINE_RULE_OFF', 'info'],
      ['BASELINE_STALE_STATUS', 'warn'],
    ]);
  });

  test('08-REQ-10 requireNote lists accepted entries without a note', () => {
    const base = file({
      a: {
        ruleId: 'cookie.no-httponly',
        subject: 's',
        severity: 'low',
        status: 'accepted',
        addedAt: '2026-01-01',
      },
    });
    expect(missingNotes(base)).toMatchObject([{ code: 'BASELINE_NOTE_REQUIRED', level: 'error' }]);
  });
});

describe('baseline without environments (D-17)', () => {
  test('08-AC-08 a file with "env" from 0.2.x is read; the next write drops the field', () => {
    const old = `${JSON.stringify({ schemaVersion: 1, generatedBy: 'x@0.2.0', env: 'qa', findings: {} }, null, 2)}\n`;
    const parsed = parseBaseline(old, 'b.json', new Set(RULE_IDS), new Set(RULE_IDS));
    expect(parsed.ok).toBe(true);
    expect(parsed.diagnostics).toEqual([]);
    const { file } = updateBaseline(parsed.ok ? parsed.file : undefined, [], [], {
      today: '2026-11-27',
      generatedBy: 'x@1',
      prune: true,
    });
    expect(serializeBaseline(file)).not.toContain('"env"');
  });
});
