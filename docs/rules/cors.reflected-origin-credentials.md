# cors.reflected-origin-credentials

**CORS reflects a foreign origin with credentials**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | high / medium                                              |
| Subject               | endpoint                                                   |
| Traffic               | browser, api                                               |
| CWE                   | [CWE-942](https://cwe.mitre.org/data/definitions/942.html) |
| OWASP Top 10          | A01:2025                                                   |
| Presets               | `recommended`, `strict`                                    |

## Why it matters

A server that echoes any Origin with credentials lets every website read the responses of a logged-in user (account data, CSRF tokens).

## How to fix

Allow only the origins of your own frontends, from a fixed list, and send credentials only to them.

- nginx: `map $http_origin $cors { "https://app.example.com" $http_origin; default ""; }` and `add_header Access-Control-Allow-Origin $cors;`
- Express: `app.use(cors({ origin: ['https://app.example.com'], credentials: true }))`
- Spring: `config.setAllowedOrigins(List.of("https://app.example.com")); config.setAllowCredentials(true);`

## False positives

Partner frontends on other origins that are allowed on purpose: add them to scope.origins or accept the finding. Passively only origins the tests used are seen; confidence is medium.

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'cors.reflected-origin-credentials': 'off' }  // or { severity: 'low' }
```

_Generated from the rule catalog by `pnpm gen:docs`._
