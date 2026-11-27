// Personal data and card numbers (06, chapters 4.13 and 4.14; 07-REQ-13): patterns, redaction of
// every evidence, the card rule and the CSRF signal of the end-of-test input.
import { describe, expect, test } from 'vitest';
import { csrfSignal } from '../../../src/collector/test-collector.ts';
import { resolveConfig } from '../../../src/core/config/index.ts';
import { Redactor } from '../../../src/core/fingerprint/index.ts';
import {
  cardBrand,
  cardNumber,
  isEmail,
  isPesel,
  isPhone,
  luhn,
  TEST_CARDS,
} from '../../../src/core/patterns/pii.ts';
import { BUILT_IN_RULES } from '../../../src/core/rules/index.ts';
import type { RuleContext } from '../../../src/core/rules/index.ts';
import type { ResponseRecord } from '../../../src/core/types/index.ts';

const redact = new Redactor({ salt: 'salt' });
const ref = { testId: 't', titlePath: ['t'], file: 'a.spec.ts', line: 1, project: 'p' };

describe('patterns', () => {
  test('PESEL: check digit and date of birth with the century in the month', () => {
    expect(isPesel('44051401458')).toBe(true); // 1944-05-14
    expect(isPesel('02210304563')).toBe(true); // 2002-01-03
    expect(isPesel('44051401459')).toBe(false); // check digit
    expect(isPesel('4405140145')).toBe(false); // length
    expect(isPesel('44133101451')).toBe(false); // month 13
  });

  test('e-mail and E.164 phone numbers', () => {
    expect(isEmail('alice@example.com')).toBe(true);
    expect(isEmail('alice@localhost')).toBe(false);
    expect(isPhone('+48601234567')).toBe(true);
    expect(isPhone('48601234567')).toBe(false);
    expect(isPhone('+4860')).toBe(false);
  });

  test('card brands by BIN and length, with the Luhn check', () => {
    expect(cardNumber('4539148803437770')).toBe('visa');
    expect(cardNumber('5412751234777778')).toBe('mastercard');
    expect(cardNumber('371449635397771')).toBe('amex');
    expect(cardNumber('4539148803437771')).toBeUndefined();
    expect(cardBrand('2221000000000009')).toBe('mastercard');
    expect(cardBrand('3528000000000007')).toBe('jcb');
    expect(cardBrand('6011000000000004')).toBe('discover');
    expect(cardBrand('41111111111111')).toBeUndefined(); // 14 digits are not Visa
  });

  test('every built-in test card is a valid card number', () => {
    for (const card of TEST_CARDS) {
      expect(luhn(card), card).toBe(true);
      expect(cardBrand(card), card).toBeDefined();
    }
  });
});

describe('07-REQ-13 personal data and card numbers are redacted in every evidence', () => {
  test('e-mail, PESEL, phone and card numbers become placeholders without the value', () => {
    const text = redact.text(
      'user alice@example.com pesel 44051401458 tel +48601234567 card 4539 1488 0343 7770 ok',
    );
    expect(text).toMatch(/\[email sha256:[0-9a-f]{6}\]/);
    expect(text).toMatch(/\[pesel sha256:[0-9a-f]{6}\]/);
    expect(text).toMatch(/\[phone sha256:[0-9a-f]{6}\]/);
    expect(text).toMatch(/\[card visa sha256:[0-9a-f]{6}\]/);
    for (const value of ['alice@example.com', '44051401458', '48601234567', '4539', '7770']) {
      expect(text).not.toContain(value);
    }
  });

  test('placeholders are stable within a run and kept when redacted again', () => {
    const once = redact.text('mail alice@example.com');
    expect(redact.text(once)).toBe(once);
    expect(redact.text('alice@example.com')).toBe(redact.pii('email', 'alice@example.com'));
  });

  test('numbers that are not personal data stay', () => {
    expect(redact.text('order 12345678901 at 1700000000000 id 4539148803437771')).toBe(
      'order 12345678901 at 1700000000000 id 4539148803437771',
    );
  });

  test('values of session parameters of auth.session-in-url are redacted (07 v0.4)', () => {
    const text = redact.text('/shop;jsessionid=A1B2C3D4/cart?sid=abc123def&q=teapot');
    expect(text).not.toContain('A1B2C3D4');
    expect(text).not.toContain('abc123def');
    expect(text).toContain('q=teapot');
  });
});

describe('06-AC-06 data.card-number', () => {
  const rule = BUILT_IN_RULES.find((r) => r.id === 'data.card-number');
  const config = resolveConfig({});
  if (rule === undefined || !config.ok) throw new Error('setup');
  const ctx: RuleContext = {
    options: config.config.rules['data.card-number']?.options ?? {},
    severity: 'high',
    confidence: 'medium',
    localDev: false,
    isHttps: true,
    inScope: () => true,
    redact,
  };
  const response = (body: string): ResponseRecord => ({
    kind: 'response',
    id: 1,
    source: 'browser',
    method: 'GET',
    url: 'https://app.test/api/me',
    endpointKey: 'GET /api/me',
    origin: 'https://app.test',
    resourceType: 'fetch',
    isNavigation: false,
    requestHeaders: [],
    status: 200,
    responseHeaders: [{ name: 'content-type', value: 'application/json' }],
    body: { contentType: 'application/json', text: body, truncated: false, sha256: 'x' },
    context: ref,
  });

  test('06-AC-06 test cards and masked numbers are not reported', () => {
    const body = JSON.stringify({
      cards: [
        '4242 4242 4242 4242',
        '4111111111111111',
        '5555-5555-5555-4444',
        '3782 822463 10005',
      ],
      masked: '**** **** **** 1111',
    });
    expect(rule.check(response(body), ctx)).toEqual([]);
  });

  test('06-AC-06 the evidence has no digit of the number (07-REQ-13)', () => {
    const findings = rule.check(response('{"card":"4539 1488 0343 7770","holder":"A"}'), ctx);
    expect(findings).toHaveLength(1);
    const evidence = findings.map((f) => redact.enforce(f).evidence[0]?.snippet ?? '').join(' ');
    expect(evidence).toMatch(/\[card visa sha256:[0-9a-f]{6}\]/);
    expect(evidence.replace(/sha256:[0-9a-f]{6}/g, '')).not.toMatch(/\d/);
  });

  test('ignoreTestCards: false reports test cards too', () => {
    const out = rule.check(response('{"card":"4242424242424242"}'), {
      ...ctx,
      options: { ignoreTestCards: false },
    });
    expect(out.map((f) => f.discriminator)).toEqual(['visa']);
  });
});

describe('the CSRF signal of the end-of-test input (06, chapter 4.14)', () => {
  const headers = (...names: string[]) => ({
    requestHeaders: names.map((name) => ({ name, value: 'x' })),
  });
  test('headers: csrf/xsrf in the name or x-requested-with', () => {
    expect(csrfSignal(headers('x-csrf-token'), undefined, null)).toBe(true);
    expect(csrfSignal(headers('x-xsrf-token'), undefined, null)).toBe(true);
    expect(csrfSignal(headers('x-requested-with'), undefined, null)).toBe(true);
    expect(csrfSignal(headers('content-type'), undefined, null)).toBe(false);
  });
  test('form fields by name only', () => {
    const none = headers();
    expect(csrfSignal(none, 'application/x-www-form-urlencoded', '_csrf=abc&email=a')).toBe(true);
    expect(csrfSignal(none, 'application/x-www-form-urlencoded', '_token=abc')).toBe(true);
    expect(csrfSignal(none, 'application/x-www-form-urlencoded', 'email=csrf')).toBe(false);
    expect(
      csrfSignal(
        none,
        'multipart/form-data',
        '--b\r\nContent-Disposition: form-data; name="csrfmiddlewaretoken"\r\n\r\nv\r\n--b--',
      ),
    ).toBe(true);
    expect(csrfSignal(none, 'text/plain', '_csrf=abc')).toBe(false);
  });
});
