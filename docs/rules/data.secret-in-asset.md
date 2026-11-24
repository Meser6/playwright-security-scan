# data.secret-in-asset

**Secret in a script, page or response**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | high / high                                                |
| Subject               | asset                                                      |
| Traffic               | browser, api                                               |
| CWE                   | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) |
| OWASP Top 10          | A04:2025                                                   |
| Presets               | `minimal`, `recommended`, `strict`                         |

## Why it matters

Anything sent to the browser or returned by the API is public. A secret key in a bundle or a response can be copied by anyone who opens the page.

## How to fix

Remove the secret from client code and responses, rotate it, and call the third-party API from the server.

- nginx: never inject secrets into served files (`sub_filter`, templated configs).
- Express: keep secrets in server-only environment variables; do not expose them through `DefinePlugin`/`import.meta.env` with a public prefix.
- Spring: keep secrets in server-side properties; never serialize them in DTOs.

## False positives

Publishable keys (Google Maps/Firebase `AIza…`) are public by design and reported with low confidence. Test fixtures and documentation examples may match; accept them as false-positive in the baseline.

## Options

| Option     | Default              |
| ---------- | -------------------- |
| `patterns` | `[]`                 |
| `ignore`   | `["generic-secret"]` |

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'data.secret-in-asset': 'off' }  // or { severity: 'low' }, or { options: { patterns: … } }
```

_Generated from the rule catalog by `pnpm gen:docs`._
