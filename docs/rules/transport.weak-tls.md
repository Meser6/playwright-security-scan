# transport.weak-tls

**Outdated TLS version**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | medium / high                                              |
| Subject               | origin                                                     |
| Traffic               | browser                                                    |
| CWE                   | [CWE-326](https://cwe.mitre.org/data/definitions/326.html) |
| OWASP Top 10          | A04:2025                                                   |
| Presets               | `minimal`, `recommended`, `strict`                         |

## Why it matters

TLS 1.0, TLS 1.1 and SSL have known weaknesses and are deprecated (RFC 8996).

## How to fix

Allow only TLS 1.2 and TLS 1.3.

- nginx: `ssl_protocols TLSv1.2 TLSv1.3;`
- Express (Node https): `https.createServer({ minVersion: 'TLSv1.2', ... })`
- Spring Boot: `server.ssl.enabled-protocols=TLSv1.2,TLSv1.3`

## False positives

None known.

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'transport.weak-tls': 'off' }  // or { severity: 'low' }
```

_Generated from the rule catalog by `pnpm gen:docs`._
