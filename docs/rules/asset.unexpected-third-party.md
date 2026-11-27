# asset.unexpected-third-party

**Script from an unexpected third-party origin**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | medium / high                                              |
| Subject               | origin                                                     |
| Traffic               | browser                                                    |
| CWE                   | [CWE-829](https://cwe.mitre.org/data/definitions/829.html) |
| OWASP Top 10          | A08:2025                                                   |
| Presets               | `minimal`, `recommended`, `strict`                         |

## Why it matters

Every script origin runs code with the full rights of your page; a new third-party origin is a new supplier that can read what users type. Keeping the list explicit makes new origins visible in review.

## How to fix

List the expected script origins in the option `allowedScriptOrigins` (patterns like `https://*.example.com` allowed); remove or self-host scripts from origins you do not expect; restrict `script-src` in the CSP to the same list.

- nginx: `add_header Content-Security-Policy "script-src 'self' https://cdn.example.com"`
- Express: `helmet.contentSecurityPolicy({ directives: { scriptSrc: ["'self'", "https://cdn.example.com"] } })`
- Spring Security: `contentSecurityPolicy(csp -> csp.policyDirectives("script-src 'self' https://cdn.example.com"))`

## False positives

A trusted CDN that is not on the list yet: add it to allowedScriptOrigins. Without the list the rule only keeps an inventory at severity info, and the baseline records the known origins.

## Options

| Option                 | Default |
| ---------------------- | ------- |
| `allowedScriptOrigins` | `[]`    |

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'asset.unexpected-third-party': 'off' }  // or { severity: 'low' }, or { options: { allowedScriptOrigins: … } }
```

_Generated from the rule catalog by `pnpm gen:docs`._
