# playwright-security-scan

Passive security scan (DAST) of the HTTP traffic of your existing Playwright e2e and API tests.
No proxy, no ZAP, no extra scenarios: run your usual test command with `PW_SEC_MODE=scan`, review
the findings, accept the current state into a committed baseline, and from then on the run fails
only when a **new** problem appears.

> **Status: under development.** Not published on npm yet.

## What it does not do

This is a passive scanner. It never sends requests of its own, so it does not test for injection
or broken access control, and it only sees the endpoints your tests visit. It does not replace a
penetration test.

## License

MIT
