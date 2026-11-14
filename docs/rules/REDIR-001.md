# REDIR-001: Redirect to a user-supplied URL

**Severity:** Medium · **CWE-601**

## What it finds
`redirect($url)`, `redirect()->to($url)`, `redirect()->away($url)` and `Redirect::to/away($url)` where `$url`
comes from the request, including the `Referer` header. A link to your domain can then send users to a
phishing page.

## How to fix
Redirect to named routes. Otherwise accept only relative paths, and reject protocol-relative ones like `//evil.com`:

```php
$to = $request->input('next', '/');
abort_unless(str_starts_with($to, '/') && ! str_starts_with($to, '//'), 400);
```

## Not reported
- `redirect()->intended()`, `redirect()->route()` and `back()`.
- The current request's own URL (`$request->fullUrl()`).
- Values checked against an allowlist.
