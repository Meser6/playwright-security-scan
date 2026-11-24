// The HTML report (09, chapter 3) in a real browser: rendering, filters, details, size and speed.
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { chromium } from '@playwright/test';
import type { Browser } from '@playwright/test';
import { afterAll, beforeAll, describe, expect, test } from 'vitest';
import { emptyCoverage } from '../../src/core/coverage.ts';
import { embedJson, renderHtml } from '../../src/core/report/html.ts';
import { BUILT_IN_RULES } from '../../src/core/rules/index.ts';
import type { ClassifiedFinding, RunReport } from '../../src/core/types/index.ts';

const ENABLED = new Set(BUILT_IN_RULES.map((r) => r.id));

function finding(i: number): ClassifiedFinding {
  const rule = BUILT_IN_RULES[i % BUILT_IN_RULES.length] as (typeof BUILT_IN_RULES)[number];
  const blocking = i % 7 === 0;
  return {
    ruleId: rule.id,
    severity: blocking ? 'high' : 'low',
    confidence: 'high',
    scope: 'endpoint',
    subject: `GET /api/items/${i}/details`,
    location: {
      origin: i % 2 === 0 ? 'https://shop.test' : 'https://api.shop.test',
      endpointKey: `GET /api/items/${i}/details`,
    },
    evidence: [
      {
        kind: 'header',
        name: 'x-test',
        snippet: `value ${i} [redacted sha256:1a2b3c] <script>alert(1)</script>`.slice(0, 200),
      },
      { kind: 'body', snippet: 'x'.repeat(150) },
    ],
    message: `Finding number ${i} on the endpoint.`,
    fingerprint: `${rule.id}|endpoint|GET /api/items/${i}/details`,
    occurrences: 3,
    firstSeen: {
      testId: `t${i}`,
      titlePath: ['suite', `test ${i}`],
      file: `tests/area-${i % 10}.spec.ts`,
      line: i + 1,
      project: 'chromium',
    },
    tests: Array.from({ length: 5 }, (_, k) => `t${i}-${k}`),
    sources: ['browser'],
    classification: blocking ? 'new' : i % 3 === 0 ? 'accepted' : 'new',
    blocking,
    ...(i % 3 === 0 && !blocking
      ? { baseline: { status: 'accepted' as const, note: 'ticket SEC-1', addedAt: '2026-11-01' } }
      : {}),
  };
}

function report(count: number): RunReport {
  const coverage = emptyCoverage();
  coverage.responses = 1234;
  coverage.documents = 40;
  coverage.origins['https://shop.test'] = { responses: 1000, documents: 40 };
  coverage.endpoints['GET /api/items/:id'] = 12;
  coverage.rulesRun['header.xcto-missing'] = 30;
  const findings = Array.from({ length: count }, (_, i) => finding(i));
  return {
    schemaVersion: 1,
    runId: 'r1',
    startedAt: '2026-11-24T20:00:00.000Z',
    finishedAt: '2026-11-24T20:05:00.000Z',
    mode: 'scan',
    pkgVersion: '0.1.0',
    playwrightVersion: '1.57.0',
    scope: { origins: ['https://shop.test'] },
    coverage,
    findings,
    resolved: [
      {
        fingerprint: 'cookie.no-secure|cookie|old@shop.test',
        ruleId: 'cookie.no-secure',
        subject: 'old@shop.test',
      },
    ],
    notCovered: [],
    testsWithoutTraffic: [
      {
        testId: 'x',
        titlePath: ['no traffic'],
        file: 'tests/x.spec.ts',
        line: 3,
        project: 'chromium',
      },
    ],
    gate: {
      minSeverity: 'medium',
      minConfidence: 'medium',
      failed: true,
      blocking: findings.filter((f) => f.blocking).map((f) => f.fingerprint),
    },
    diagnostics: [{ code: 'BODY_READ_FAILED', level: 'info', message: 'one body' }],
    outcome: {
      schemaVersion: 1,
      code: 1,
      name: 'NEW_FINDINGS',
      testsPassed: true,
      newBlocking: 143,
      newNonBlocking: 0,
      expired: 0,
      resolved: 1,
    },
  };
}

let browser: Browser;
const dir = mkdtempSync(join(tmpdir(), 'pw-sec-html-'));
beforeAll(async () => {
  browser = await chromium.launch();
});
afterAll(async () => {
  await browser?.close();
});

describe('HTML report (09, chapter 3)', () => {
  test('09-AC-02 1000 findings: under 5 MB, no external resources, opens in under 2 s', async () => {
    const html = renderHtml(report(1000), BUILT_IN_RULES, ENABLED);
    expect(Buffer.byteLength(html)).toBeLessThan(5 * 1024 * 1024);
    expect(html).not.toMatch(/<(script|link|img|iframe)[^>]+(src|href)=["']?https?:/i);
    expect(html).not.toMatch(/@import|url\(/);
    const file = join(dir, 'big.html');
    writeFileSync(file, html);
    const page = await browser.newPage();
    const external: string[] = [];
    page.on('request', (r) => {
      if (!r.url().startsWith('file:')) external.push(r.url());
    });
    const started = Date.now();
    await page.goto(pathToFileURL(file).href);
    await page.locator('#rows tr.row').first().waitFor();
    expect(Date.now() - started).toBeLessThan(2000);
    expect(external).toEqual([]);
    expect(await page.locator('#rows tr.row').count()).toBe(1000);
    await page.close();
  });

  test('header, filters, details with Why/Fix/Accept, coverage and the "not covered" box', async () => {
    const file = join(dir, 'small.html');
    writeFileSync(file, renderHtml(report(20), BUILT_IN_RULES, ENABLED));
    const page = await browser.newPage();
    const errors: string[] = [];
    page.on('pageerror', (e) => errors.push(e.message));
    await page.goto(pathToFileURL(file).href);
    await expect.poll(() => page.locator('#head').textContent()).toContain('NEW_FINDINGS · code 1');
    expect(await page.locator('body').textContent()).toContain('What this scan does not cover');
    // Blocking findings come first.
    expect(await page.locator('#rows tr.row').first().textContent()).toContain('blocking');
    await page.selectOption('#f-class', 'accepted');
    const accepted = await page.locator('#rows tr.row').count();
    expect(accepted).toBeGreaterThan(0);
    expect(accepted).toBeLessThan(20);
    await page.selectOption('#f-class', '');
    await page.locator('#rows tr.row').first().click();
    const detail = page.locator('#rows tr.detail.open');
    await expect.poll(() => detail.textContent()).toContain('Why');
    const text = (await detail.textContent()) ?? '';
    expect(text).toContain('Fix');
    expect(text).toContain('False positives');
    expect(text).toContain('Add to security-baseline.json');
    expect(text).toContain('(first seen)');
    // Evidence is shown as text, never run.
    expect(await page.locator('#rows script').count()).toBe(0);
    const coverage = (await page.locator('#coverage').textContent()) ?? '';
    expect(coverage).toContain('1234 responses in scope');
    expect(coverage).toContain('Tests without traffic in scope (1)');
    expect(coverage).toContain('Resolved baseline entries (1)');
    expect(errors).toEqual([]);
    await page.close();
  });

  test('embedded JSON cannot close the script element', () => {
    expect(embedJson({ a: '</script><script>alert(1)</script>' })).not.toContain('</script>');
  });
});
