// The HTML report (09, chapter 3) in a real browser: size and speed, tabs, filters, sorting,
// details with the rule reference, and the page without JavaScript.
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { chromium } from '@playwright/test';
import type { Browser, Page } from '@playwright/test';
import { afterAll, beforeAll, describe, expect, test } from 'vitest';
import { renderHtmlReport } from '../../src/html/index.ts';
import { bigInput, statesInput } from './fixtures.ts';

let browser: Browser;
const dir = mkdtempSync(join(tmpdir(), 'pw-sec-html-'));
const statesFile = join(dir, 'states.html');
writeFileSync(statesFile, renderHtmlReport(statesInput()));

beforeAll(async () => {
  browser = await chromium.launch();
});
afterAll(async () => {
  await browser?.close();
});

async function open(
  file: string,
  hash = '',
  javaScriptEnabled = true,
): Promise<{ page: Page; errors: string[] }> {
  const context = await browser.newContext({ javaScriptEnabled });
  const page = await context.newPage();
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(m.text());
  });
  await page.goto(pathToFileURL(file).href + hash);
  return { page, errors };
}

const rows = (page: Page) => page.locator('#table-findings > tbody:not([hidden]) > tr:first-child');

describe('HTML report (09, chapter 3)', () => {
  test('09-AC-02 1000 findings: under 5 MB, no external resources, opens in under 2 s', async () => {
    const html = renderHtmlReport(bigInput(1000));
    expect(Buffer.byteLength(html)).toBeLessThan(5 * 1024 * 1024);
    expect(html).not.toMatch(/<(script|link|img|iframe)[^>]+(src|href)=["']?https?:/i);
    const file = join(dir, 'big.html');
    writeFileSync(file, html);
    const context = await browser.newContext();
    const page = await context.newPage();
    const external: string[] = [];
    page.on('request', (r) => {
      if (!r.url().startsWith('file:') && !r.url().startsWith('data:')) external.push(r.url());
    });
    const started = Date.now();
    await page.goto(pathToFileURL(file).href);
    await page.locator('[data-count]').getByText('showing 1000 of 1000').waitFor();
    expect(Date.now() - started).toBeLessThan(2000);
    expect(external).toEqual([]);
    expect(await rows(page).count()).toBe(1000);
    await context.close();
  });

  test('tabs, counter tile filter, chips, search, sorting and reset', async () => {
    const { page, errors } = await open(statesFile);
    await expect
      .poll(() => page.locator('#tab-findings-link').getAttribute('aria-selected'))
      .toBe('true');
    expect(await page.locator('#tab-coverage').isHidden()).toBe(true);
    // Default order: new blocking, expired, new, baseline entries.
    expect(await rows(page).locator('td:last-child').allTextContents()).toEqual([
      'new · blocking',
      'expired',
      'new',
      'accepted',
      'accepted',
      'wontfix',
      'false positive',
    ]);
    // A tile opens the Findings tab filtered to its classes.
    await page.locator('#tab-coverage-link').click();
    expect(await page.locator('#tab-coverage').isVisible()).toBe(true);
    await page.locator('.kpi a[data-filter^="accepted"]').click();
    await expect.poll(() => rows(page).count()).toBe(4);
    expect(await page.locator('[data-count]').textContent()).toBe('showing 4 of 7');
    expect(page.url()).toMatch(/#tab=findings$/u);
    await page.locator('.toolbar [data-reset]').click();
    await page.locator('button[data-f="sev"][data-v="high"]').click();
    await expect.poll(() => rows(page).count()).toBe(1);
    await page.locator('.toolbar [data-reset]').click();
    await page.locator('input[type="search"]').fill('theme@');
    await expect.poll(() => rows(page).count()).toBe(1);
    await page.locator('input[type="search"]').fill('nothing matches this');
    await expect.poll(() => page.locator('[data-none]').isVisible()).toBe(true);
    await page.locator('[data-none] [data-reset]').click();
    await expect.poll(() => rows(page).count()).toBe(7);
    // Sorting by rule.
    await page.locator('th[data-sort="rule"] button').click();
    expect(await page.locator('th[data-sort="rule"]').getAttribute('aria-sort')).toBe('ascending');
    const rules = await rows(page).locator('.rk .key').allTextContents();
    expect(rules).toEqual([...rules].sort());
    // Keyboard on the tab list.
    await page.locator('#tab-findings-link').focus();
    await page.keyboard.press('ArrowRight');
    await expect
      .poll(() => page.locator('#tab-coverage-link').getAttribute('aria-selected'))
      .toBe('true');
    expect(errors).toEqual([]);
    await page.context().close();
  });

  test('09-AC-05 a row click opens the dialog; Esc, Close and the backdrop close it and restore the focus; Next goes on', async () => {
    const { page, errors } = await open(statesFile);
    const dialog = page.locator('dialog#finding-dialog');
    const row = rows(page).first();
    const focusOnRow = () =>
      page.evaluate(() => document.activeElement?.closest('tbody')?.dataset['fp'] ?? null);
    const fp = await page.locator('#table-findings > tbody').first().getAttribute('data-fp');

    await row.click();
    await expect.poll(() => dialog.getAttribute('open')).toBe('');
    expect(await page.evaluate(() => document.activeElement?.id)).toBe('dlg-title');
    expect(await dialog.getAttribute('aria-labelledby')).toBe('dlg-title');
    expect(await page.locator('#dlg-pos').textContent()).toBe('Finding 1 of 7');
    const text = (await dialog.textContent()) ?? '';
    for (const part of [
      'Fingerprint',
      'Location',
      'Evidence',
      'Tests',
      'first seen',
      'Why',
      'Fix',
      'False positives',
      'References',
      'Accept',
      'Copy link',
    ]) {
      expect(text, part).toContain(part);
    }
    expect(page.url()).toContain(`#finding=${encodeURIComponent(fp ?? '')}`);
    await page.keyboard.press('Escape');
    await expect.poll(() => dialog.getAttribute('open')).toBeNull();
    await expect.poll(focusOnRow).toBe(fp);
    expect(page.url()).toMatch(/#tab=findings$/u);
    // The block went back to its row.
    expect(await page.locator('#table-findings > tbody').first().locator('.kd .kh').count()).toBe(
      1,
    );

    await row.click();
    await page.locator('[data-act="close"]').click();
    await expect.poll(() => dialog.getAttribute('open')).toBeNull();
    await expect.poll(focusOnRow).toBe(fp);

    await row.click();
    // The top left corner is outside the centred dialog: a click on the backdrop.
    await page.mouse.click(4, 4);
    await expect.poll(() => dialog.getAttribute('open')).toBeNull();
    await expect.poll(focusOnRow).toBe(fp);

    // Next follows the visible rows with the filters.
    await page.locator('button[data-f="c"][data-v="accepted"]').click();
    await expect.poll(() => rows(page).count()).toBe(2);
    await rows(page).first().click();
    expect(await page.locator('#dlg-pos').textContent()).toBe('Finding 1 of 2');
    expect(await page.locator('[data-act="prev"]').isDisabled()).toBe(true);
    await page.locator('[data-act="next"]').click();
    expect(await page.locator('#dlg-pos').textContent()).toBe('Finding 2 of 2');
    expect(await page.locator('[data-act="next"]').isDisabled()).toBe(true);
    const second = await rows(page).nth(1).getAttribute('data-fp');
    expect(page.url()).toContain(`#finding=${encodeURIComponent(second ?? '')}`);
    await page.keyboard.press('Escape');
    expect(errors).toEqual([]);
    await page.context().close();
  });

  test('09-AC-06 #finding=<fingerprint> opens the dialog of that finding; an unknown one is announced', async () => {
    const input = statesInput();
    const fp = input.report.findings.find((f) => f.classification === 'wontfix')?.fingerprint ?? '';
    const { page, errors } = await open(statesFile, `#finding=${encodeURIComponent(fp)}`);
    const dialog = page.locator('dialog#finding-dialog');
    await expect.poll(() => dialog.getAttribute('open')).toBe('');
    expect(await dialog.locator('.fp').textContent()).toBe(fp);
    expect(await dialog.textContent()).toContain('wontfix');
    const unknown = await open(statesFile, `#finding=${encodeURIComponent('no|such|finding')}`);
    await expect
      .poll(() => unknown.page.locator('#status').textContent())
      .toBe('Finding not found in this report');
    expect(await unknown.page.locator('dialog#finding-dialog').getAttribute('open')).toBeNull();
    // A selector-like fingerprint is compared as text, never used as a selector.
    const odd = await open(statesFile, `#finding=${encodeURIComponent('"]*,body')}`);
    await expect
      .poll(() => odd.page.locator('#status').textContent())
      .toBe('Finding not found in this report');
    const run = await open(statesFile, '#tab=run');
    await expect.poll(() => run.page.locator('#tab-run').isVisible()).toBe(true);
    const bad = await open(statesFile, '#tab=nope');
    await expect
      .poll(() => bad.page.locator('#status').textContent())
      .toBe('Tab not found in this report');
    expect([...errors, ...unknown.errors, ...odd.errors, ...run.errors, ...bad.errors]).toEqual([]);
    for (const p of [page, unknown.page, odd.page, run.page, bad.page]) await p.context().close();
  });

  test('09-AC-09 without JavaScript every tab is shown and every finding has its details', async () => {
    const { page } = await open(statesFile, '', false);
    for (const id of ['findings', 'coverage', 'run']) {
      expect(await page.locator(`#tab-${id}`).isVisible(), id).toBe(true);
    }
    expect(await page.locator('.toolbar').isHidden()).toBe(true);
    const bodies = page.locator('#table-findings > tbody');
    expect(await bodies.count()).toBe(7);
    for (let i = 0; i < 7; i++) {
      const body = bodies.nth(i);
      await body.locator('summary').click();
      const text = (await body.locator('details').textContent()) ?? '';
      expect(text).toContain('Fingerprint');
      expect(text).toContain('Rule reference of');
    }
    await page.locator('#rule-docs > summary').click();
    expect(await page.locator('#rule-docs .rdoc').count()).toBe(7);
    expect(await page.locator('#rule-docs').textContent()).toContain('False positives');
    expect(await page.locator('body').textContent()).toContain('What this scan does not cover');
    await page.context().close();
  });
});
