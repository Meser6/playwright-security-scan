# Rules

57 passive rules; 55 in the default `recommended` preset.

| Rule                                                                                                                          | Severity | Confidence | Traffic      | CWE     |
| ----------------------------------------------------------------------------------------------------------------------------- | -------- | ---------- | ------------ | ------- |
| [`header.csp-missing`](header.csp-missing.md) — Content-Security-Policy missing                                               | medium   | high       | browser      | 693     |
| [`header.csp-unsafe`](header.csp-unsafe.md) — Unsafe Content-Security-Policy                                                  | medium   | high       | browser      | 693     |
| [`header.csp-missing-directives`](header.csp-missing-directives.md) — CSP without object-src or base-uri                      | low      | high       | browser      | 693     |
| [`header.csp-report-only`](header.csp-report-only.md) — CSP in report-only mode only                                          | info     | high       | browser      | 693     |
| [`header.clickjacking`](header.clickjacking.md) — No clickjacking protection                                                  | medium   | medium     | browser      | 1021    |
| [`header.hsts-missing`](header.hsts-missing.md) — Strict-Transport-Security missing                                           | low      | high       | browser, api | 319     |
| [`header.hsts-weak`](header.hsts-weak.md) — Strict-Transport-Security max-age too short                                       | low      | high       | browser, api | 319     |
| [`header.xcto-missing`](header.xcto-missing.md) — X-Content-Type-Options: nosniff missing                                     | low      | high       | browser, api | 693     |
| [`header.referrer-policy-unsafe`](header.referrer-policy-unsafe.md) — Unsafe Referrer-Policy                                  | low      | high       | browser      | 200     |
| [`header.content-type-missing`](header.content-type-missing.md) — Content-Type missing                                        | low      | high       | browser, api | 16      |
| [`header.permissions-policy-missing`](header.permissions-policy-missing.md) (strict) — Permissions-Policy missing             | info     | high       | browser      | 693     |
| [`header.coop-missing`](header.coop-missing.md) (strict) — Cross-Origin-Opener-Policy missing                                 | info     | high       | browser      | 693     |
| [`cookie.no-secure`](cookie.no-secure.md) — Session cookie without Secure                                                     | medium   | high       | browser, api | 614     |
| [`cookie.no-httponly`](cookie.no-httponly.md) — Session cookie without HttpOnly                                               | medium   | high       | browser, api | 1004    |
| [`cookie.samesite-none`](cookie.samesite-none.md) — Session cookie with SameSite=None                                         | low      | medium     | browser, api | 1275    |
| [`cookie.samesite-missing`](cookie.samesite-missing.md) — Cookie without SameSite                                             | info     | high       | browser, api | 1275    |
| [`cookie.long-lived-session`](cookie.long-lived-session.md) — Long-lived session cookie                                       | low      | medium     | browser, api | 613     |
| [`cookie.non-session-insecure`](cookie.non-session-insecure.md) — Cookie without Secure                                       | info     | medium     | browser, api | 614     |
| [`cors.wildcard-credentials`](cors.wildcard-credentials.md) — CORS wildcard with credentials                                  | high     | high       | browser, api | 942     |
| [`cors.reflected-origin-credentials`](cors.reflected-origin-credentials.md) — CORS reflects a foreign origin with credentials | high     | medium     | browser, api | 942     |
| [`cors.null-origin`](cors.null-origin.md) — CORS allows the null origin                                                       | medium   | high       | browser, api | 942     |
| [`cors.wildcard-sensitive`](cors.wildcard-sensitive.md) — CORS wildcard on an authenticated endpoint                          | low      | low        | browser, api | 942     |
| [`transport.cleartext`](transport.cleartext.md) — Application served over HTTP                                                | medium   | high       | browser, api | 319     |
| [`transport.mixed-content`](transport.mixed-content.md) — Mixed content                                                       | medium   | high       | browser      | 311     |
| [`transport.form-to-http`](transport.form-to-http.md) — Form submits over HTTP                                                | medium   | high       | browser      | 319     |
| [`transport.weak-tls`](transport.weak-tls.md) — Outdated TLS version                                                          | medium   | high       | browser      | 326     |
| [`data.token-in-url`](data.token-in-url.md) — Token in URL                                                                    | medium   | high       | browser, api | 598     |
| [`data.jwt-alg-none`](data.jwt-alg-none.md) — JWT with alg none                                                               | critical | high       | browser, api | 347     |
| [`data.jwt-no-exp`](data.jwt-no-exp.md) — JWT without expiry                                                                  | medium   | high       | browser, api | 613     |
| [`data.jwt-long-lived`](data.jwt-long-lived.md) — Long-lived JWT                                                              | low      | high       | browser, api | 613     |
| [`data.jwt-sensitive-claims`](data.jwt-sensitive-claims.md) — Sensitive data in JWT claims                                    | medium   | medium     | browser, api | 312     |
| [`data.password-in-response`](data.password-in-response.md) — Password or hash in a response                                  | high     | medium     | browser, api | 200     |
| [`data.secret-in-asset`](data.secret-in-asset.md) — Secret in a script, page or response                                      | high     | high       | browser, api | 798     |
| [`data.token-in-storage`](data.token-in-storage.md) — Token in Web Storage                                                    | low      | medium     | browser      | 922     |
| [`disclosure.stack-trace`](disclosure.stack-trace.md) — Stack trace in a response                                             | medium   | high       | browser, api | 209     |
| [`disclosure.sql-error`](disclosure.sql-error.md) — SQL error in a response                                                   | high     | medium     | browser, api | 209, 89 |
| [`disclosure.server-version`](disclosure.server-version.md) — Server version disclosed                                        | low      | high       | browser, api | 200     |
| [`disclosure.debug-mode`](disclosure.debug-mode.md) — Debug page exposed                                                      | medium   | medium     | browser, api | 489     |
| [`disclosure.private-ip`](disclosure.private-ip.md) — Private IP address disclosed                                            | low      | medium     | browser, api | 200     |
| [`disclosure.directory-listing`](disclosure.directory-listing.md) — Directory listing                                         | low      | high       | browser, api | 548     |
| [`disclosure.source-map`](disclosure.source-map.md) — Source map exposed                                                      | info     | high       | browser      | 540     |
| [`disclosure.server-error`](disclosure.server-error.md) — Server error during tests                                           | info     | high       | browser, api | 755     |
| [`browser.csp-violation`](browser.csp-violation.md) — CSP violation in the browser                                            | info     | high       | browser      | 693     |
| [`asset.sri-missing`](asset.sri-missing.md) — Third-party script or style without SRI                                         | low      | high       | browser      | 353     |
| [`browser.open-redirect-candidate`](browser.open-redirect-candidate.md) — Open redirect candidate                             | medium   | medium     | browser, api | 601     |
| [`browser.reflected-param`](browser.reflected-param.md) — Query parameter reflected in HTML                                   | info     | low        | browser      | 79      |
| [`auth.session-fixation`](auth.session-fixation.md) — Session id not renewed at login                                         | medium   | medium     | browser      | 384     |
| [`auth.session-in-url`](auth.session-in-url.md) — Session id in URL                                                           | medium   | high       | browser, api | 598     |
| [`cache.sensitive-cacheable`](cache.sensitive-cacheable.md) — Authenticated response may be cached                            | medium   | medium     | browser, api | 524     |
| [`browser.csrf-missing`](browser.csrf-missing.md) — State-changing request without CSRF protection                            | medium   | low        | browser      | 352     |
| [`asset.unexpected-third-party`](asset.unexpected-third-party.md) — Script from an unexpected third-party origin              | medium   | high       | browser      | 829     |
| [`data.pii-in-url`](data.pii-in-url.md) — Personal data in URL                                                                | medium   | medium     | browser, api | 598     |
| [`data.card-number`](data.card-number.md) — Payment card number in a response                                                 | high     | medium     | browser, api | 359     |
| [`cookie.broad-domain`](cookie.broad-domain.md) — Session cookie shared with subdomains                                       | low      | high       | browser, api | 565     |
| [`disclosure.internal-hostname`](disclosure.internal-hostname.md) — Internal host name disclosed                              | low      | medium     | browser, api | 200     |
| [`disclosure.verbose-error-json`](disclosure.verbose-error-json.md) — Error details in a JSON response                        | medium   | medium     | browser, api | 209     |
| [`browser.password-form-get`](browser.password-form-get.md) — Password form submitted with GET                                | medium   | high       | browser      | 598     |
