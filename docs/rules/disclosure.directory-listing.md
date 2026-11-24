# disclosure.directory-listing

**Directory listing**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | low / high                                                 |
| Subject               | endpoint                                                   |
| Traffic               | browser, api                                               |
| CWE                   | [CWE-548](https://cwe.mitre.org/data/definitions/548.html) |
| OWASP Top 10          | A02:2025                                                   |
| Presets               | `minimal`, `recommended`, `strict` (medium)                |

## Why it matters

A directory listing exposes every file of a folder, including backups and files that were never linked.

## How to fix

Turn directory listings off.

- nginx: `autoindex off;`
- Express: no `serve-index`; `express.static(dir, { index: false })` without a listing middleware
- Spring Boot: no `ResourceHttpRequestHandler` listings; `spring.web.resources.add-mappings` only for public assets

## False positives

Public download folders meant to be browsed: accept them with a note.

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'disclosure.directory-listing': 'off' }  // or { severity: 'low' }
```

_Generated from the rule catalog by `pnpm gen:docs`._
