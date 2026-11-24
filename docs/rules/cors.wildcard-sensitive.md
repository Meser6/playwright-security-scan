# cors.wildcard-sensitive

**CORS wildcard on an authenticated endpoint**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | low / low                                                  |
| Subject               | endpoint                                                   |
| Traffic               | browser, api                                               |
| CWE                   | [CWE-942](https://cwe.mitre.org/data/definitions/942.html) |
| OWASP Top 10          | —                                                          |
| Presets               | `recommended`, `strict`                                    |

## Why it matters

An authenticated endpoint readable from any origin may expose user data if the credentials are also sent automatically or are guessable.

## How to fix

Allow only the origins of your own frontends, from a fixed list, and send credentials only to them.

- nginx: `map $http_origin $cors { "https://app.example.com" $http_origin; default ""; }` and `add_header Access-Control-Allow-Origin $cors;`
- Express: `app.use(cors({ origin: ['https://app.example.com'], credentials: true }))`
- Spring: `config.setAllowedOrigins(List.of("https://app.example.com")); config.setAllowCredentials(true);`

## False positives

Public APIs that authenticate with an API key on purpose. Reported with low confidence.

## Options

| Option               | Default                                                                                                                        |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `sessionNamePattern` | `"(sess\|sid\|auth\|token\|jwt\|login\|remember\|connect\\.sid\|PHPSESSID\|JSESSIONID\|ASP\\.NET_SessionId\|laravel_session)"` |

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'cors.wildcard-sensitive': 'off' }  // or { severity: 'low' }, or { options: { sessionNamePattern: … } }
```

_Generated from the rule catalog by `pnpm gen:docs`._
