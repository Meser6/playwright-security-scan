// Visual design of the HTML report (09-REQ-16, 09-REQ-17): color tokens equal to the perf report,
// contrast of the new tokens, no colors outside tokens, no style attributes, icons, escaping.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, test } from 'vitest';
import { renderHtmlReport } from '../../../src/html/index.ts';
import { ICON_NAMES } from '../../../src/html/icons.ts';
import { bigInput, statesInput } from '../../browser/fixtures.ts';

const CSS = readFileSync(
  join(import.meta.dirname, '../../../src/html/template/styles.css'),
  'utf8',
);
const PERF = readFileSync(join(import.meta.dirname, '../../fixtures/perf-tokens.css'), 'utf8');
const DARK_MEDIA = '@media screen and (prefers-color-scheme: dark)';

/** Custom properties of the first `:root { … }` after `from`. */
function tokens(css: string, from: number): Record<string, string> {
  const start = css.indexOf(':root {', from);
  const body = css.slice(start, css.indexOf('}', start));
  return Object.fromEntries(
    [...body.matchAll(/(--[\w-]+):\s*([^;]+);/gu)].map((m) => [m[1], (m[2] ?? '').trim()]),
  );
}

const LIGHT = tokens(CSS, 0);
const DARK = tokens(CSS, CSS.indexOf(DARK_MEDIA));
const PERF_LIGHT = tokens(PERF, 0);
const PERF_DARK = tokens(PERF, PERF.indexOf(DARK_MEDIA));

/** A token's value in a theme, following var() aliases. */
function resolve(theme: Record<string, string>, name: string): string {
  const value = theme[name] ?? LIGHT[name] ?? '';
  const alias = /^var\((--[\w-]+)\)$/u.exec(value);
  return alias === null ? value : resolve(theme, alias[1] ?? '');
}

function luminance(hex: string): number {
  const [r, g, b] = [1, 3, 5].map((i) => {
    const c = parseInt(hex.slice(i, i + 2), 16) / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  }) as [number, number, number];
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrast(a: string, b: string): number {
  const [x, y] = [luminance(a), luminance(b)].sort((p, q) => q - p) as [number, number];
  return (x + 0.05) / (y + 0.05);
}

describe('tokens (09-REQ-16)', () => {
  test('09-AC-08 every perf token has the perf value in the light and the dark theme', () => {
    expect(Object.keys(PERF_LIGHT).length).toBeGreaterThan(40);
    for (const [name, value] of Object.entries(PERF_LIGHT)) expect(LIGHT[name], name).toBe(value);
    for (const [name, value] of Object.entries(PERF_DARK)) expect(DARK[name], name).toBe(value);
  });

  test('09-AC-08 the stylesheet has no color values outside the token definitions', () => {
    const rules = CSS.replace(/\/\*.*?\*\//gsu, '').replace(/:root \{[^}]*\}/gu, '');
    expect(rules.match(/#[0-9a-f]{3,8}\b/giu) ?? []).toEqual([]);
    // Only translucent shades (the dialog backdrop and color-mix) besides tokens.
    for (const m of rules.matchAll(/(?:rgba?|hsla?)\([^)]*\)/gu)) {
      expect(m[0], m[0]).toMatch(/\/\s*\d+%?\)$/u);
    }
  });

  test('09-AC-08 severity pills reach 4.5:1 in both themes', () => {
    const failures: string[] = [];
    for (const [theme, t] of [
      ['light', LIGHT],
      ['dark', DARK],
    ] as const) {
      for (const s of ['critical', 'high', 'medium', 'low', 'info']) {
        const ratio = contrast(resolve(t, `--sev-${s}`), resolve(t, `--sev-${s}-bg`));
        if (ratio < 4.5) failures.push(`${theme} ${s}: ${ratio.toFixed(2)}`);
      }
    }
    expect(failures).toEqual([]);
  });

  test('09-AC-08 the page has no style attributes and loads nothing from outside', () => {
    for (const page of [renderHtmlReport(statesInput()), renderHtmlReport(bigInput(30))]) {
      expect(page.replace(/"[^"]*"/gu, '""')).not.toMatch(/<[a-z]+\s[^>]*\sstyle=/u);
      expect(page).not.toMatch(/@import|url\(|<img|@font-face/u);
      for (const m of page.matchAll(/<link[^>]*\shref="([^"]*)"|\ssrc="([^"]*)"/gu)) {
        expect(m[1] ?? m[2], m[0]).toMatch(/^data:/u);
      }
      expect(page.replaceAll('&#39;', "'")).toMatch(
        /content="default-src 'none'; script-src 'sha256-[^']+'; style-src 'sha256-[^']+'; img-src data:"/u,
      );
    }
  });
});

describe('layout (09-REQ-17)', () => {
  const page = renderHtmlReport(statesInput());

  test('app bar, verdict card, six counter tiles, three tabs and the footer', () => {
    const bar = /<header class="appbar">.*?<\/header>/su.exec(page)?.[0] ?? '';
    expect(bar).toContain('<b>playwright-security-scan</b> <span class="ver">v0.2.0</span>');
    expect(bar).toContain('mode <b>scan</b>');
    expect(bar).toContain('scope <b>https://shop.test</b> +1');
    expect(page).toMatch(/<section class="hero t-bad" aria-labelledby="vh">/u);
    expect(page).toContain('<h1 class="status" id="vh">FAILED</h1>');
    expect(page).toContain('NEW_FINDINGS (code 1): 1 new blocking finding ≥ medium');
    const tiles = [...page.matchAll(/<div class="kpi[^"]*"><dt>(.*?)<\/dt>/gu)].map((m) => m[1]);
    expect(tiles).toEqual([
      'New, blocking',
      'New, non-blocking',
      'Accepted',
      'Expired',
      'Resolved',
      'Not covered',
    ]);
    expect(page).toContain('<a href="#tab-findings" data-filter="blocking">1</a>');
    const tabs = [...page.matchAll(/data-tab="([a-z]+)"/gu)].map((m) => m[1]);
    expect(tabs).toEqual(['findings', 'coverage', 'run']);
    expect(page).toContain(
      'https://github.com/Meser6/playwright-security-scan/blob/main/docs/reports.md',
    );
  });

  test('every <use> points to a symbol of the sprite; the logo is a data: favicon too', () => {
    const defined = new Set([...page.matchAll(/<symbol id="([^"]+)"/gu)].map((m) => m[1]));
    expect(defined).toEqual(new Set(ICON_NAMES.map((n) => `i-${n}`)));
    for (const m of page.matchAll(/<use href="#(i-[^"]+)"/gu)) expect(defined.has(m[1])).toBe(true);
    expect(page).toMatch(/<link rel="icon" type="image\/svg\+xml" href="data:image\/svg\+xml,/u);
  });

  test('report values are escaped, never markup', () => {
    const input = statesInput();
    const first = input.report.findings[0];
    if (first === undefined) throw new Error('fixture');
    first.message = '<script>alert(1)</script>';
    first.evidence = [{ kind: 'body', snippet: '<img src=x onerror=alert(1)>' }];
    const html = renderHtmlReport(input);
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
    expect(html).not.toContain('<img src=x');
    expect(html.match(/<script/gu)).toHaveLength(1);
  });

  test('the page is deterministic', () => {
    expect(renderHtmlReport(statesInput())).toBe(page);
  });
});
