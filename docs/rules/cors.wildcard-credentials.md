# cors.wildcard-credentials

**CORS wildcard with credentials**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | high / high                                                |
| Subject               | endpoint                                                   |
| Traffic               | browser, api                                               |
| CWE                   | [CWE-942](https://cwe.mitre.org/data/definitions/942.html) |
| OWASP Top 10          | A01:2025                                                   |
| Presets               | `minimal`, `recommended`, `strict`                         |

## Why it matters

Access-Control-Allow-Origin: * with credentials shows a CORS setup that trusts every site; browsers reject the pair, but the configuration usually reflects origins elsewhere.

## How to fix

Allow only the origins of your own frontends, from a fixed list, and send credentials only to them.

- nginx: `map $http_origin $cors { "https://app.example.com" $http_origin; default ""; }` and `add_header Access-Control-Allow-Origin $cors;`
- Express: `app.use(cors({ origin: ['https://app.example.com'], credentials: true }))`
- Spring: `config.setAllowedOrigins(List.of("https://app.example.com")); config.setAllowCredentials(true);`

## False positives

None known.

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'cors.wildcard-credentials': 'off' }  // or { severity: 'low' }
```

_Generated from the rule catalog by `pnpm gen:docs`._
