# CSRF-001: CSRF protection disabled for browser routes

**Severity:** High for `*`, Medium for wildcards, Low for single paths · **CWE-352**

## What it finds
CSRF protection switched off for a path that doesn't look like a webhook or callback. That covers:
- entries in `validateCsrfTokens(except: [...])` (Laravel 11+)
- entries in `VerifyCsrfToken::$except` (Laravel 10 and earlier)
- removing the CSRF middleware from the `web` group
- `->withoutMiddleware(VerifyCsrfToken::class)` on state-changing routes

## How to fix
Exclude only the exact webhook paths that need it (`stripe/webhook`). Browser forms should send `@csrf`.

## Not reported
Paths that look machine-to-machine: webhooks, payment callbacks (Stripe, PayPal, Mollie...), `api/*`,
and SSO/OAuth callbacks.
