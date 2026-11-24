# browser.csp-violation

**CSP violation in the browser**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | info / high                                                |
| Subject               | origin                                                     |
| Traffic               | browser                                                    |
| CWE                   | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) |
| OWASP Top 10          | —                                                          |
| Presets               | `minimal`, `recommended`, `strict` (low)                   |

## Why it matters

A violation means the page tried to load or run something the policy forbids: a broken feature, a policy to adjust, or an injection attempt.

## How to fix

Find the blocked resource or inline script and either allow it explicitly (a nonce or hash, an origin in the right directive) or remove it.

- nginx: adjust the `add_header Content-Security-Policy` value
- Express: adjust the `helmet.contentSecurityPolicy` directives
- Spring Security: adjust `contentSecurityPolicy(csp -> csp.policyDirectives(…))`

## False positives

Browser extensions and the browser's own requests can cause violations; /favicon.ico is ignored.

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'browser.csp-violation': 'off' }  // or { severity: 'low' }
```

_Generated from the rule catalog by `pnpm gen:docs`._
