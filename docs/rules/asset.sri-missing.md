# asset.sri-missing

**Third-party script or style without SRI**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | low / high                                                 |
| Subject               | asset                                                      |
| Traffic               | browser                                                    |
| CWE                   | [CWE-353](https://cwe.mitre.org/data/definitions/353.html) |
| OWASP Top 10          | A08:2025                                                   |
| Presets               | `minimal`, `recommended`, `strict` (medium)                |

## Why it matters

A script or stylesheet from a third-party server runs with the rights of your page; if that server or CDN is compromised, so is your page.

## How to fix

Add `integrity="sha384-…"` and `crossorigin="anonymous"` to third-party `<script>` and `<link rel="stylesheet">` tags, or host the files yourself.

- nginx: serve third-party files from your own origin (`location /vendor/ { … }`)
- Express: generate the tags with integrity hashes (e.g. `webpack-subresource-integrity`)
- Spring: add `integrity` attributes in the templates (Thymeleaf `th:attr`)

## False positives

Scripts that change on every request (analytics loaders) cannot have SRI: accept them with a note.

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'asset.sri-missing': 'off' }  // or { severity: 'low' }
```

_Generated from the rule catalog by `pnpm gen:docs`._
