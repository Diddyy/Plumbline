# Benchmark

Plumbline 0.1.0 against popular open-source Laravel apps (shallow clones of the default branch,
November 2026). Reproduce with `php bench/run.php`.

| App | Commit | PHP + Blade files | Critical / High | Low (review) |
|---|---|---:|---:|---:|
| BookStack | `0b6b667` | 1,676 | 0 | 11 |
| koel | `c2d0f08` | 1,289 | 0 | 0 |
| Monica | `dab7427` | 1,133 | 0 | 0 |
| LinkAce | `ebdcb38` | 970 | 0 | 13 |
| Pixelfed | `ecd835d` | 2,366 | 0 | 27 |
| Firefly III | `e1a90bf` | 1,697 | 0 | 37 |
| Speedtest Tracker | `3ee5a58` | 349 | 0 | 0 |
| solidtime | `9c4e9f3` | 504 | 0 | 0 |
| laravel/laravel, react-starter-kit | | | 0 | 0 |

Medium findings: 2 across all apps, from one pattern in one app. It is being verified by hand and,
if confirmed, will be reported privately to the maintainers. The app isn't named here until a fix ships.

## Triage

- **Critical/High: 0.** None of these mature apps had a Critical or High finding. Plumbline reported none.
- **Low (88):** all are XSS-001 "review" findings: `{!! $model->field !!}` or a translation with
  dynamic replacements, printing stored data without escaping. They're accurate (the output is
  unescaped). Whether each is exploitable depends on whether the stored HTML was sanitised on the
  way in, which a static tool can't see. Hide them with `--min-severity=medium`.

## How the numbers moved during development

Every false positive found on these apps, and on ~35 private Laravel apps, became a fixture in
`tests/Fixtures/*/safe` before the rule was changed. That covered helper-based authorization
(`$this->ensureOwned()`), FormRequest rules that check the current user, signed routes, local-only
routes, same-origin redirect checks (`str_starts_with`, `parse_url`, fixed-host URLs, `'/path/'.$id`),
HTML helper functions in Blade, HIBP's SHA-1 API, webhook controllers, DAV endpoints, private upload
disks and embedded third-party apps.

For example, Firefly III went from 707 Low findings to 37 when Blade calls to HTML-building helpers
stopped being reported.
