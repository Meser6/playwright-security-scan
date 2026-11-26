import { describe, expect, test } from 'vitest';
import { emptyCoverage } from '../../src/core/coverage.ts';
import type { Finding, OutcomeFile, RunReport } from '../../src/core/types/index.ts';
import { createAjv, readSchema, SCHEMA_FILES, validator } from './schemas.ts';

const finding: Finding = {
  ruleId: 'cookie.no-httponly',
  severity: 'medium',
  confidence: 'high',
  scope: 'cookie',
  subject: 'session_id@app.example.com',
  location: { origin: 'https://app.example.com', endpointKey: 'POST /login' },
  evidence: [
    { kind: 'cookie', name: 'session_id', snippet: 'session_id=[redacted sha256:1a2b3c]; Path=/' },
  ],
  message: 'Session cookie session_id is readable by JavaScript.',
  fingerprint: 'cookie.no-httponly|cookie|session_id@app.example.com',
  occurrences: 2,
  firstSeen: {
    testId: 't1',
    titlePath: ['login'],
    file: 'tests/login.spec.ts',
    line: 5,
    project: 'chromium',
  },
  tests: ['t1'],
  sources: ['browser'],
};

const outcome: OutcomeFile = {
  schemaVersion: 1,
  code: 1,
  env: null,
  name: 'NEW_FINDINGS',
  testsPassed: true,
  newBlocking: 2,
  newNonBlocking: 5,
  expired: 0,
  resolved: 1,
};

describe('JSON schemas (02)', () => {
  const ajv = createAjv();

  test('every schema compiles in strict mode and has a pkg.invalid $id', () => {
    for (const file of SCHEMA_FILES) {
      expect(readSchema(file).$id).toBe(`https://pkg.invalid/schemas/${file}`);
      expect(() => validator(ajv, file)).not.toThrow();
    }
  });

  test('02-REQ-05 test attachment', () => {
    const validate = validator(ajv, 'attachment.schema.json');
    const doc = {
      schemaVersion: 1,
      findings: [finding],
      coverage: emptyCoverage(),
      diagnostics: [],
    };
    expect(validate(doc), JSON.stringify(validate.errors)).toBe(true);
    expect(validate({ ...doc, findings: [{ ...finding, classification: 'new' }] })).toBe(false);
    const long = { ...finding, evidence: [{ kind: 'body', snippet: 'x'.repeat(201) }] };
    expect(validate({ ...doc, findings: [long] })).toBe(false);
  });

  test('02-REQ-02 baseline file of the spec example; wontfix needs a note', () => {
    const validate = validator(ajv, 'baseline.schema.json');
    const doc = {
      schemaVersion: 1,
      generatedBy: 'playwright-security-scan@0.1.0',
      findings: {
        'cookie.no-httponly|cookie|session_id@app.example.com': {
          ruleId: 'cookie.no-httponly',
          subject: 'session_id@app.example.com',
          severity: 'medium',
          status: 'accepted',
          note: 'Frontend reads the cookie; ticket SEC-123',
          until: '2027-02-01',
          addedAt: '2026-11-24',
        },
      },
    };
    expect(validate(doc), JSON.stringify(validate.errors)).toBe(true);
    const wontfix = structuredClone(doc);
    const entry = wontfix.findings['cookie.no-httponly|cookie|session_id@app.example.com'];
    entry.status = 'wontfix';
    delete (entry as { note?: string }).note;
    expect(validate(wontfix)).toBe(false);
  });

  test('02, chapter 7 outcome file', () => {
    const validate = validator(ajv, 'outcome.schema.json');
    expect(validate(outcome), JSON.stringify(validate.errors)).toBe(true);
    expect(validate({ ...outcome, code: 5 })).toBe(false);
  });

  test('02, chapter 6 run report with classified findings', () => {
    const validate = validator(ajv, 'run-report.schema.json');
    const report: RunReport = {
      schemaVersion: 1,
      runId: 'r1',
      startedAt: '2026-11-24T20:00:00.000Z',
      finishedAt: '2026-11-24T20:01:00.000Z',
      mode: 'scan',
      env: null,
      pkgVersion: '0.1.0',
      playwrightVersion: '1.57.0',
      scope: { origins: ['https://app.example.com'] },
      coverage: emptyCoverage(),
      findings: [
        {
          ...finding,
          classification: 'accepted',
          blocking: false,
          baseline: {
            status: 'accepted',
            addedAt: '2026-11-24',
            until: '2026-12-01',
            expiresInDays: 7,
          },
        },
      ],
      resolved: [],
      notCovered: [],
      testsWithoutTraffic: [],
      gate: { minSeverity: 'medium', minConfidence: 'medium', failed: false, blocking: [] },
      diagnostics: [{ code: 'NO_TRAFFIC', level: 'error', message: 'x' }],
      outcome,
    };
    expect(validate(report), JSON.stringify(validate.errors)).toBe(true);
    expect(
      validate({
        ...report,
        findings: [{ ...finding, classification: 'new', blocking: true, extra: 1 }],
      }),
    ).toBe(false);
  });
});
