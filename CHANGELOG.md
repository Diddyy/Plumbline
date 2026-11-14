# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- AUTHZ-002: Livewire actions that change a browser-chosen record without an authorization check.
  Experimental: not yet benchmarked on real Livewire apps.
- `php artisan plumbline:scan` and `plumbline:rules` via package auto-discovery.
- Support for Symfony Console 6.4 and 8 (Laravel 10 and 13).

### Fixed
- Open-redirect checks respect custom validation rules (e.g. `new IsValidOriginUrl()`) and FormRequests that build `$rules` in a variable.
- PHP 8.5 partial function application no longer crashes the scanner.

## [0.1.0] - 2026-11-14

### Added
- AST-based taint engine that tracks request input within each function: `$request->input()`,
  `request()`, superglobals, route parameters, Livewire public properties and actions, and
  client upload names. It understands validation rules, allowlists (`in_array`, `match`) and casts.
- Route index: `bootstrap/app.php`, `RouteServiceProvider`, nested groups, prefixes,
  `require`d route files, resources, controller middleware (Laravel 11+ `HasMiddleware` and
  Laravel 10 constructor style), middleware aliases and groups.
- 12 rules: SQLI-001, CMD-001, DESER-001, MASS-001, AUTHZ-001, AUTH-001, XSS-001, REDIR-001,
  UPLOAD-001, CSRF-001, CFG-001, CRYPTO-001.
- Console, JSON, SARIF 2.1.0 and GitHub annotation output.
- Inline suppressions with a required reason, and baseline files.
- Composite GitHub Action that uploads SARIF to code scanning.
