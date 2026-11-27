// data.* rules about personal data and card numbers (06, chapters 4.13 and 4.14).
import {
  CARD_IN_TEXT,
  cardNumber,
  isEmail,
  isPesel,
  isPhone,
  TEST_CARDS,
} from '../patterns/pii.ts';
import type { CardBrand } from '../patterns/pii.ts';
import type { RawFinding, ResponseRecord } from '../types/index.ts';
import { finding, manifestOf } from './types.ts';
import type { BuiltInRule, RuleInput } from './types.ts';

const isRecord = (input: RuleInput): input is ResponseRecord => input.kind === 'response';

/** Query parameters with `+` kept (not decoded as a space): `+48…` is a phone number. */
function rawQuery(url: string): [string, string][] {
  const q = url.indexOf('?');
  if (q < 0) return [];
  const hash = url.indexOf('#', q);
  const query = url.slice(q + 1, hash < 0 ? undefined : hash);
  const decode = (text: string): string => {
    try {
      return decodeURIComponent(text);
    } catch {
      return text;
    }
  };
  return query
    .split('&')
    .filter((p) => p !== '')
    .map((p) => {
      const eq = p.indexOf('=');
      return eq < 0 ? [decode(p), ''] : [decode(p.slice(0, eq)), decode(p.slice(eq + 1))];
    });
}

type PiiKind = 'email' | 'pesel' | 'phone';
const PII_LABEL: Record<PiiKind, string> = {
  email: 'an e-mail address',
  pesel: 'a PESEL number',
  phone: 'a phone number',
};

function piiKind(value: string): PiiKind | undefined {
  const v = value.trim();
  if (isEmail(v)) return 'email';
  if (isPesel(v)) return 'pesel';
  if (isPhone(v)) return 'phone';
  return undefined;
}

const PII = manifestOf('data.pii-in-url');
export const piiInUrl: BuiltInRule = {
  id: PII.id,
  manifest: PII,
  appliesTo: {},
  check(input, ctx) {
    if (!isRecord(input)) return [];
    const out: RawFinding[] = [];
    const seen = new Set<string>();
    for (const [name, value] of rawQuery(input.url)) {
      if (value === '' || seen.has(name)) continue;
      const kind = piiKind(value);
      if (kind === undefined) continue;
      seen.add(name);
      out.push(
        finding(ctx, PII, {
          subject: input.endpointKey,
          discriminator: name,
          location: { origin: input.origin, endpointKey: input.endpointKey, param: name },
          evidence: [
            { kind: 'url', name, snippet: `${name}=${ctx.redact.pii(kind, value.trim())}` },
          ],
          message: `${input.endpointKey} carries ${PII_LABEL[kind]} in the query parameter "${name}".`,
        }),
      );
    }
    return out;
  },
  docs: {
    title: PII.title,
    why: 'URLs end up in browser history, server, proxy and analytics logs and the Referer header of linked sites, so personal data in the query leaks to everyone who reads them (GDPR).',
    fix: [
      'Send personal data in a POST body or refer to the person by an opaque id; use POST for search forms with personal data.',
      '',
      '- nginx: do not log the query of such endpoints (`log_format` without `$args`) while fixing the client',
      '- Express: accept the value in `req.body` (POST), not `req.query`',
      '- Spring: `@PostMapping` with `@RequestBody` instead of `@GetMapping` with `@RequestParam`',
    ].join('\n'),
    falsePositives:
      'E-mail confirmation links that must carry the address (prefer a signed token), and test data with made-up addresses: accept them with a note.',
  },
};

const CARD = manifestOf('data.card-number');
const CARD_TYPES = ['document', 'xhr', 'fetch', 'api'];
export const cardNumberInResponse: BuiltInRule = {
  id: CARD.id,
  manifest: CARD,
  appliesTo: { resourceTypes: CARD_TYPES },
  needsBody: CARD_TYPES,
  check(input, ctx) {
    if (!isRecord(input) || input.body === undefined) return [];
    const ignoreTest = ctx.options.ignoreTestCards !== false;
    const text = input.body.text;
    const found = new Map<CardBrand, { index: number; length: number }>();
    for (const m of text.matchAll(CARD_IN_TEXT)) {
      const digits = m[0].replace(/[ -]/g, '');
      const brand = cardNumber(digits);
      if (brand === undefined || found.has(brand)) continue;
      if (ignoreTest && TEST_CARDS.has(digits)) continue;
      found.set(brand, { index: m.index, length: m[0].length });
    }
    return [...found].map(([brand, at]) =>
      finding(ctx, CARD, {
        subject: input.endpointKey,
        discriminator: brand,
        location: { origin: input.origin, endpointKey: input.endpointKey },
        // The snippet goes through the final filter, which replaces every card number.
        evidence: [{ kind: 'body', snippet: ctx.redact.snippet(text, at.index, at.length) }],
        message: `${input.endpointKey} returns a full ${brand} card number.`,
      }),
    );
  },
  docs: {
    title: CARD.title,
    why: 'A full card number in a response is cardholder data (PCI DSS): whoever sees the response, its cache or its logs can use the card. Applications show only the last four digits.',
    fix: [
      'Keep card numbers with the payment provider (tokens) and return only a masked form such as `**** **** **** 1234`.',
      '',
      '- nginx: nothing to configure; the API must not return the number',
      '- Express: map the card to `{ brand, last4 }` before `res.json(...)`',
      '- Spring: a DTO with `last4` only, or `@JsonIgnore` on the number field',
    ].join('\n'),
    falsePositives:
      'Demo data with numbers that are not on the built-in list of provider test cards, and long numeric ids that happen to pass the Luhn check: accept them with a note. Known test cards are skipped (option ignoreTestCards).',
  },
};
