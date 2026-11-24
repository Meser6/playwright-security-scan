# browser.reflected-param

**Query parameter reflected in HTML**

|                       |                                                          |
| --------------------- | -------------------------------------------------------- |
| Severity / confidence | info / low                                               |
| Subject               | endpoint                                                 |
| Traffic               | browser                                                  |
| CWE                   | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) |
| OWASP Top 10          | A05:2025                                                 |
| Presets               | `recommended`, `strict` (low)                            |

## Why it matters

A reflected parameter is where reflected XSS starts; it is only a candidate until an active test (stage E3) confirms it, so it never blocks.

## How to fix

Encode every reflected value for its HTML context (templates with auto-escaping) and keep a strict CSP.

- nginx: nothing to configure; add a CSP (`add_header Content-Security-Policy "script-src 'self'"`)
- Express: render with an auto-escaping template engine; never concatenate `req.query` into HTML
- Spring: Thymeleaf `th:text` (escaped), not `th:utext`

## False positives

Safe reflections such as search terms shown escaped (letters and digits look the same encoded). Reported as info with low confidence.

## Options

| Option      | Default |
| ----------- | ------- |
| `minLength` | `6`     |

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'browser.reflected-param': 'off' }  // or { severity: 'low' }, or { options: { minLength: … } }
```

_Generated from the rule catalog by `pnpm gen:docs`._
