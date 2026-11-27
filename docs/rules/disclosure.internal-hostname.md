# disclosure.internal-hostname

**Internal host name disclosed**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | low / medium                                               |
| Subject               | endpoint                                                   |
| Traffic               | browser, api                                               |
| CWE                   | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) |
| OWASP Top 10          | A02:2025                                                   |
| Presets               | `recommended`, `strict`                                    |

## Why it matters

Internal host names (Kubernetes services, corporate DNS, .internal zones) map the network behind the application and give targets for SSRF and lateral movement.

## How to fix

Remove internal host names from responses and headers: upstream names, debug fields, absolute URLs built from internal addresses.

- nginx: `proxy_hide_header X-Upstream;` (and similar), `proxy_redirect` to rewrite internal `Location` values
- Express: build absolute URLs from the public host (`trust proxy`), never from the internal one
- Spring Boot: `server.forward-headers-strategy=framework`; no infrastructure fields in DTOs

## False positives

API documentation and examples that mention internal names on purpose. Apps served from such a host are skipped; on localhost the confidence is low.

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'disclosure.internal-hostname': 'off' }  // or { severity: 'low' }
```

_Generated from the rule catalog by `pnpm gen:docs`._
