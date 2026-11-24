# data.password-in-response

**Password or hash in a response**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | high / medium                                              |
| Subject               | endpoint                                                   |
| Traffic               | browser, api                                               |
| CWE                   | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) |
| OWASP Top 10          | A01:2025                                                   |
| Presets               | `recommended`, `strict`                                    |

## Why it matters

Password hashes and salts in API responses can be cracked offline; they should never leave the server.

## How to fix

Exclude credential fields from the response model (a DTO or serializer allow-list).

- nginx: nothing to configure; fix the application
- Express: `const { password, passwordHash, ...safe } = user; res.json(safe)` or a schema serializer
- Spring: `@JsonIgnore` on the field or a response DTO without it

## False positives

"hash" or "salt" fields that are not credentials (content hashes, cache keys): accept them as false-positive.

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'data.password-in-response': 'off' }  // or { severity: 'low' }
```

_Generated from the rule catalog by `pnpm gen:docs`._
