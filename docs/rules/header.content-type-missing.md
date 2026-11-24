# header.content-type-missing

**Content-Type missing**

|                       |                                                          |
| --------------------- | -------------------------------------------------------- |
| Severity / confidence | low / high                                               |
| Subject               | endpoint                                                 |
| Traffic               | browser, api                                             |
| CWE                   | [CWE-16](https://cwe.mitre.org/data/definitions/16.html) |
| OWASP Top 10          | A02:2025                                                 |
| Presets               | `minimal`, `recommended`, `strict` (medium)              |

## Why it matters

Without Content-Type the browser guesses the type of the response, and a guessed HTML or script type can turn data into executable content.

## How to fix

Send the right Content-Type (e.g. `application/json; charset=utf-8`) with every response that has a body.

- nginx: `default_type application/octet-stream;` and correct `types` for static files
- Express: `res.type('application/json')` or `res.json(...)` instead of `res.end(...)`
- Spring: `@GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)`

## False positives

Empty bodies are not reported. Binary downloads should still declare a type.

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'header.content-type-missing': 'off' }  // or { severity: 'low' }
```

_Generated from the rule catalog by `pnpm gen:docs`._
