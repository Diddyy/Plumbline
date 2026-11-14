# Plumbline

[![CI](https://github.com/Diddyy/Plumbline/actions/workflows/ci.yml/badge.svg)](https://github.com/Diddyy/Plumbline/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**A precision-first security scanner for Laravel. The scanner that doesn't cry wolf.**

Measured on 8 popular open-source Laravel apps (BookStack, Pixelfed, Firefly III, Monica, koel...):
**zero Critical/High false positives**. See [BENCHMARK.md](BENCHMARK.md).

Most static scanners match patterns: they flag every `DB::raw()` and every `{!! !!}`, and teams
learn to ignore them. Plumbline reads your code the way Laravel runs it, and only speaks up
when it can explain *why* something is exploitable:

```
 app/Http/Controllers/SearchController.php
  CRITICAL  SQLI-001 line 22
     User input from $request->query('sort') reaches raw SQL in orderByRaw(). Pass it as a
     binding instead, e.g. ->whereRaw('lower(name) = ?', [$name]).
     │ return Post::query()->orderByRaw($column.' desc')->get();

 app/Http/Controllers/PostController.php
  HIGH      AUTHZ-001 line 18
     DELETE /posts/{post} (PostController@destroy) deletes the Post chosen in the URL ($post)
     without an authorization check, so any signed-in user can do this to any Post.
     Add $this->authorize('delete', $post) or ->can('delete,post') on the route.
     │ $post->delete();
```

## What makes it different

- **It knows Laravel.** It rebuilds your routes statically from `bootstrap/app.php`, `RouteServiceProvider`,
  groups, prefixes, resources, `require`d route files and controller middleware. It knows which routes
  need a login and which check authorization. It reads FormRequest `rules()` and `authorize()`, model
  `$fillable`/`$guarded`, global scopes, and Livewire public properties and `#[Locked]`.
- **It tracks real data flow.** A real PHP AST (nikic/php-parser), with taint tracked through
  assignments, string building, `sprintf`, loops and closures. Casts, `$request->integer()`, validation
  rules (`integer`, `in:`, `Rule::in`, `uuid`...), `in_array` allowlists and `match` all clear taint.
- **It stays quiet when unsure.** Unknown functions are treated as clean. Custom route middleware might be
  an access check, so access rules skip those routes. That trade-off is deliberate.
- **Precision is tested.** Every rule ships with a vulnerable fixture (every marked line must be
  reported, and nothing else) and a safe fixture (zero findings). The official `laravel/laravel` skeleton
  and `react-starter-kit` must come back with zero findings.

## Install

```bash
composer require --dev diddyy/plumbline
php artisan plumbline:scan        # or: vendor/bin/plumbline scan
```

Works with Laravel 10 and later (Symfony Console 6.4, 7 or 8) on PHP 8.3+. The artisan commands register
through package auto-discovery.

It never boots your app or runs your code, so it's safe to point at anything.

## Rules

| ID | Finds | Severity |
|---|---|---|
| [SQLI-001](docs/rules/SQLI-001.md) | User input in raw SQL (`DB::select`, `*Raw()`, `DB::raw`) | Critical |
| [CMD-001](docs/rules/CMD-001.md) | User input in shell commands | Critical |
| [DESER-001](docs/rules/DESER-001.md) | `unserialize()` on user input | High |
| [MASS-001](docs/rules/MASS-001.md) | `$request->all()` written to an unguarded model, a builder `update()`, or one with `is_admin`/`role` in `$fillable` | High |
| [AUTHZ-001](docs/rules/AUTHZ-001.md) | Signed-in route updates or deletes a URL-chosen model with no authorization check (IDOR) | High |
| [AUTHZ-002](docs/rules/AUTHZ-002.md) | Livewire action updates or deletes a record chosen by the browser (`$wire.delete(42)`) with no authorization check *(experimental)* | High |
| [AUTH-001](docs/rules/AUTH-001.md) | Route with no auth middleware that changes existing records | High |
| [XSS-001](docs/rules/XSS-001.md) | `{!! !!}` with request data (High), unsafe Markdown (Medium), other raw output (Low) | High–Low |
| [REDIR-001](docs/rules/REDIR-001.md) | Redirects to user-supplied URLs | Medium |
| [UPLOAD-001](docs/rules/UPLOAD-001.md) | Uploads stored under the client's file name and extension | Medium/High |
| [CSRF-001](docs/rules/CSRF-001.md) | CSRF disabled for paths that aren't webhooks | High–Low |
| [CFG-001](docs/rules/CFG-001.md) | `APP_DEBUG=true` for production | High |
| [CRYPTO-001](docs/rules/CRYPTO-001.md) | Fast hashes on passwords, `rand()` tokens, timing-unsafe token comparison | High–Low |

## Usage

```bash
vendor/bin/plumbline scan [path]
  --format=console|json|sarif|github
  --output=report.sarif
  --min-severity=medium            # hide lower-severity findings
  --fail-on=high                   # exit 1 only for high/critical (default: any finding)
  --rules=SQLI-001,AUTHZ-001       # run only these
  --skip-rules=XSS-001
  --exclude=legacy                 # extra directories to skip
  --baseline=plumbline-baseline.json
  --generate-baseline=plumbline-baseline.json

vendor/bin/plumbline rules         # list rules
```

### Adopting it on an existing app

Record what's there today, then fail CI only on new findings:

```bash
vendor/bin/plumbline scan --generate-baseline=plumbline-baseline.json
vendor/bin/plumbline scan --baseline=plumbline-baseline.json
```

Baseline entries match on rule + file + source line, not line number, so unrelated edits don't
bring old findings back.

### Suppressing a finding

Put a comment on the line or the line above. A reason is required:

```php
// plumbline-ignore SQLI-001: $column is checked against the schema in ColumnGuard
return Post::orderByRaw($column)->get();
```

```blade
{{-- plumbline-ignore XSS-001: body is purified on save --}}
{!! $post->body !!}
```

## GitHub code scanning

```yaml
name: Security
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  plumbline:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: shivammathur/setup-php@v2
        with: { php-version: '8.3' }
      - uses: Diddyy/Plumbline@v0
        with:
          fail-on: high
```

Findings appear in the repository's **Security → Code scanning** tab and as annotations on pull requests.

## Limits (honest ones)

- Taint tracking stays within one function. A value passed into a helper method and used there is not followed yet.
- AUTHZ-001 can't know whether every signed-in user is meant to be an admin. Suppress it, or use a baseline, if that's your app.
- Plumbline doesn't replace a dependency audit. Run `composer audit` as well.

## Contributing

False-positive reports are the most valuable contribution. See [CONTRIBUTING.md](CONTRIBUTING.md):
adding a rule means writing the rule, its fixtures, and its docs.

## License

MIT
