# transport.mixed-content

**Mixed content**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | medium / high                                              |
| Subject               | asset                                                      |
| Traffic               | browser                                                    |
| CWE                   | [CWE-311](https://cwe.mitre.org/data/definitions/311.html) |
| OWASP Top 10          | A04:2025                                                   |
| Presets               | `minimal`, `recommended`, `strict`                         |

## Why it matters

An HTTP resource on an HTTPS page can be read or replaced on the network; a replaced script takes over the page.

## How to fix

Load every resource over HTTPS (or with a relative URL) and add `upgrade-insecure-requests` to the CSP.

- nginx: `add_header Content-Security-Policy "upgrade-insecure-requests" always;`
- Express: `helmet.contentSecurityPolicy({ directives: { upgradeInsecureRequests: [] } })`
- Spring Security: `http.headers(h -> h.contentSecurityPolicy(c -> c.policyDirectives("upgrade-insecure-requests")))`

## False positives

Links (<a href="http://…">) are not mixed content and are not reported.

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'transport.mixed-content': 'off' }  // or { severity: 'low' }
```

_Generated from the rule catalog by `pnpm gen:docs`._
