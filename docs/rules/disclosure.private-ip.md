# disclosure.private-ip

**Private IP address disclosed**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | low / medium                                               |
| Subject               | endpoint                                                   |
| Traffic               | browser, api                                               |
| CWE                   | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) |
| OWASP Top 10          | —                                                          |
| Presets               | `recommended`, `strict`                                    |

## Why it matters

Internal addresses map the network behind the application and help attacks such as SSRF.

## How to fix

Remove internal addresses from responses and headers (load balancer, upstream and debug fields).

- nginx: `proxy_hide_header X-Backend-Server;` and similar upstream headers
- Express: do not return infrastructure fields; `app.set("trust proxy", …)` instead of echoing addresses
- Spring Boot: exclude infrastructure fields from DTOs; `server.forward-headers-strategy=framework`

## False positives

Version strings that look like addresses, and apps served from a private address (skipped).

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'disclosure.private-ip': 'off' }  // or { severity: 'low' }
```

_Generated from the rule catalog by `pnpm gen:docs`._
