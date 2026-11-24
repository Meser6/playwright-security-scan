# disclosure.source-map

**Source map exposed**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | info / high                                                |
| Subject               | asset                                                      |
| Traffic               | browser                                                    |
| CWE                   | [CWE-540](https://cwe.mitre.org/data/definitions/540.html) |
| OWASP Top 10          | —                                                          |
| Presets               | `minimal`, `recommended`, `strict` (low)                   |

## Why it matters

Source maps publish the original source code, comments included; the package does not download the map (passive only).

## How to fix

Do not deploy source maps to production, or serve them only to authenticated developers.

- nginx: `location ~* \.map$ { deny all; }`
- Express: build without `devtool: "source-map"`, or `app.use(/\.map$/, (req, res) => res.sendStatus(404))`
- Spring Boot: exclude `*.map` from `spring.web.resources.static-locations`

## False positives

Open-source frontends that publish their code anyway. Reported as info.

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'disclosure.source-map': 'off' }  // or { severity: 'low' }
```

_Generated from the rule catalog by `pnpm gen:docs`._
