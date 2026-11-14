# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - unreleased

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
