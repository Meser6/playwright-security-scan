# data.card-number

**Payment card number in a response**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | high / medium                                              |
| Subject               | endpoint                                                   |
| Traffic               | browser, api                                               |
| CWE                   | [CWE-359](https://cwe.mitre.org/data/definitions/359.html) |
| OWASP Top 10          | A04:2025                                                   |
| Presets               | `recommended`, `strict`                                    |

## Why it matters

A full card number in a response is cardholder data (PCI DSS): whoever sees the response, its cache or its logs can use the card. Applications show only the last four digits.

## How to fix

Keep card numbers with the payment provider (tokens) and return only a masked form such as `**** **** **** 1234`.

- nginx: nothing to configure; the API must not return the number
- Express: map the card to `{ brand, last4 }` before `res.json(...)`
- Spring: a DTO with `last4` only, or `@JsonIgnore` on the number field

## False positives

Demo data with numbers that are not on the built-in list of provider test cards, and long numeric ids that happen to pass the Luhn check: accept them with a note. Known test cards are skipped (option ignoreTestCards).

## Options

| Option            | Default |
| ----------------- | ------- |
| `ignoreTestCards` | `true`  |

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'data.card-number': 'off' }  // or { severity: 'low' }, or { options: { ignoreTestCards: … } }
```

_Generated from the rule catalog by `pnpm gen:docs`._
