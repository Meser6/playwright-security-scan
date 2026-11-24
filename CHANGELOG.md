# Changelog

All notable changes to this project are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `withSecurity()` and `defineSecurityConfig()` (`playwright-security-scan/config`): `PW_SEC_MODE=scan|baseline` turns the scan on, the package reporter is appended, and the package config is validated with suggestions for mistyped options and rule ids. Without `PW_SEC_MODE` the Playwright config is returned unchanged. `PW_SEC_CONFIG` points to another config file.
- Rule presets `recommended` (default), `strict` and `minimal`.
- JSON Schemas of the file formats (`schemas/`, exported as `playwright-security-scan/schemas/*`): test attachment, baseline file, run report and outcome file.
