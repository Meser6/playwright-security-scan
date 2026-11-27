# data.pii-in-url

**Personal data in URL**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | medium / medium                                            |
| Subject               | endpoint                                                   |
| Traffic               | browser, api                                               |
| CWE                   | [CWE-598](https://cwe.mitre.org/data/definitions/598.html) |
| OWASP Top 10          | A04:2025                                                   |
| Presets               | `recommended`, `strict`                                    |

## Why it matters

URLs end up in browser history, server, proxy and analytics logs and the Referer header of linked sites, so personal data in the query leaks to everyone who reads them (GDPR).

## How to fix

Send personal data in a POST body or refer to the person by an opaque id; use POST for search forms with personal data.

- nginx: do not log the query of such endpoints (`log_format` without `$args`) while fixing the client
- Express: accept the value in `req.body` (POST), not `req.query`
- Spring: `@PostMapping` with `@RequestBody` instead of `@GetMapping` with `@RequestParam`

## False positives

E-mail confirmation links that must carry the address (prefer a signed token), and test data with made-up addresses: accept them with a note.

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'data.pii-in-url': 'off' }  // or { severity: 'low' }
```

_Generated from the rule catalog by `pnpm gen:docs`._
