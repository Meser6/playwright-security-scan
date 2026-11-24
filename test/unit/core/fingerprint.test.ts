import { describe, expect, test } from 'vitest';
import {
  cookieSubject,
  fingerprintOf,
  normalizeAssetUrl,
  normalizeName,
  normalizeOrigin,
} from '../../../src/core/fingerprint/index.ts';
import { sha256 } from '../../../src/core/hash/index.ts';

describe('fingerprints (07, chapter 3)', () => {
  test('07-REQ-05 readable fingerprints of the spec examples', () => {
    expect(
      fingerprintOf({
        ruleId: 'header.hsts-missing',
        scope: 'origin',
        subject: 'https://shop.example.com',
      }),
    ).toBe('header.hsts-missing|origin|https://shop.example.com');
    expect(
      fingerprintOf({
        ruleId: 'cookie.no-httponly',
        scope: 'cookie',
        subject: 'session_id@shop.example.com',
      }),
    ).toBe('cookie.no-httponly|cookie|session_id@shop.example.com');
    expect(
      fingerprintOf({
        ruleId: 'data.token-in-url',
        scope: 'endpoint',
        subject: 'GET /auth/callback?code&token',
        discriminator: 'token',
      }),
    ).toBe('data.token-in-url|endpoint|GET /auth/callback?code&token|token');
  });

  test('07-REQ-07 severity and confidence are not part of the fingerprint', () => {
    const a = { ruleId: 'header.csp-missing', scope: 'origin' as const, subject: 'https://a.test' };
    expect(fingerprintOf({ ...a, severity: 'low' } as never)).toBe(
      fingerprintOf({ ...a, severity: 'high' } as never),
    );
  });

  test('07-REQ-08 a fingerprint over 512 characters is shortened with a hash of the whole', () => {
    const subject = `GET /${'a'.repeat(600)}`;
    const full = `disclosure.stack-trace|endpoint|${subject}`;
    const print = fingerprintOf({ ruleId: 'disclosure.stack-trace', scope: 'endpoint', subject });
    expect(print).toBe(`${full.slice(0, 480)}…#${sha256(full).slice(0, 8)}`);
    expect(print.length).toBeLessThanOrEqual(512);
  });
});

describe('normalization of names, origins and assets (07, chapter 2)', () => {
  test('07-REQ-02 origins are lowercase without the default port', () => {
    expect(normalizeOrigin('HTTPS://Shop.Example.com:443/path?q')).toBe('https://shop.example.com');
    expect(normalizeOrigin('http://localhost:3000/')).toBe('http://localhost:3000');
    expect(normalizeOrigin('ftp://x.test')).toBeNull();
    expect(normalizeOrigin('not a url')).toBeNull();
  });

  test.each([
    ['_ga_3XK21', '_ga_*'],
    ['session_8f14e45f', 'session_*'],
    ['wp_user_123456', 'wp_user_*'],
    ['wordpress_logged_in_5c0f4e3e1d2b4a6f8e9d0c1b2a3f4e5d', 'wordpress_logged_in_*'],
    ['ab-3f2504e0-4f89-11d3-9a0c-0305e82c3301', 'ab-*'],
    ['session_id', 'session_id'],
    ['XSRF-TOKEN', 'XSRF-TOKEN'],
    ['cart_v2', 'cart_v2'],
    ['_ga', '_ga'],
    ['123456', '123456'],
  ])('07-REQ-03 name %s → %s', (name, expected) => {
    expect(normalizeName(name)).toBe(expected);
  });

  test('07-REQ-03 cookie domain without the leading dot, lowercase', () => {
    expect(cookieSubject('session_8f14e45f', '.Shop.Example.COM')).toBe(
      'session_*@shop.example.com',
    );
  });

  test.each([
    [
      'https://shop.example.com/static/main.3f2a9c1b.js?v=1#x',
      'https://shop.example.com/static/main.*.js',
    ],
    ['https://shop.example.com/chunk-ABCD1234.js', 'https://shop.example.com/chunk-*.js'],
    [
      'https://shop.example.com/_next/static/chunks/pages/app-0123456789abcdef.js',
      'https://shop.example.com/_next/static/chunks/pages/app-*.js',
    ],
    [
      'https://shop.example.com/assets/index-BxK9mQ2z.css',
      'https://shop.example.com/assets/index-*.css',
    ],
    ['https://cdn.example.com/jquery-3.7.1.min.js', 'https://cdn.example.com/jquery-3.7.1.min.js'],
    ['https://shop.example.com/app.bundle.js', 'https://shop.example.com/app.bundle.js'],
  ])('07-REQ-04 asset %s → %s', (url, expected) => {
    expect(normalizeAssetUrl(url)).toBe(expected);
  });

  test('07-AC-02 a rebuilt frontend (new chunk hashes) keeps the asset fingerprints', () => {
    const before = [
      'https://app.test/assets/index-a1b2c3d4.js',
      'https://app.test/static/js/main.9f8e7d6c.chunk.js',
    ];
    const after = [
      'https://app.test/assets/index-e5f6a7b8.js',
      'https://app.test/static/js/main.1a2b3c4d.chunk.js',
    ];
    const prints = (urls: string[]) =>
      urls.map((url) =>
        fingerprintOf({
          ruleId: 'data.secret-in-asset',
          scope: 'asset',
          subject: normalizeAssetUrl(url) ?? '',
          discriminator: 'aws-access-key',
        }),
      );
    expect(prints(after)).toEqual(prints(before));
  });
});
