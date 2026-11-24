# browser.open-redirect-candidate

**Open redirect candidate**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | medium / medium                                            |
| Subject               | endpoint                                                   |
| Traffic               | browser, api                                               |
| CWE                   | [CWE-601](https://cwe.mitre.org/data/definitions/601.html) |
| OWASP Top 10          | A01:2025                                                   |
| Presets               | `recommended`, `strict`                                    |

## Why it matters

A redirect that goes wherever a parameter says lets phishing links start on your trusted domain; confirmation needs an active test (stage E3).

## How to fix

Redirect only to relative paths or to an allow-list of hosts.

- nginx: do not build `return 302 $arg_next;` from parameters
- Express: `const next = allowed.has(new URL(req.query.next, base).host) ? req.query.next : '/'`
- Spring Security: `DefaultRedirectStrategy` with `setContextRelative(true)` or a validated target

## False positives

SSO flows that redirect to registered client URLs on purpose: accept them with a note.

## Options

| Option       | Default                                                                                                                                                                          |
| ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `paramNames` | `["next","url","redirect","redirect_uri","redirect_url","redirectUrl","return","returnUrl","return_url","returnTo","return_to","continue","dest","destination","goto","target"]` |

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'browser.open-redirect-candidate': 'off' }  // or { severity: 'low' }, or { options: { paramNames: … } }
```

_Generated from the rule catalog by `pnpm gen:docs`._
