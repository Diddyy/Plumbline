# AUTH-001: Unauthenticated route changes existing records

**Severity:** High · **CWE-306**

## What it finds
A `POST`, `PUT`, `PATCH` or `DELETE` route with no authentication middleware whose action updates or deletes
*existing* records. That covers a bound model, `Model::find($id)->delete()`, `Model::where(...)->update()`
and `Model::destroy($id)`.

## How to fix
Put the route behind `auth` (or `auth:sanctum`). If it really must be public, use a signed URL (`signed` middleware).

## Not reported
- Public routes that only *create* records (contact forms, sign-ups, comments).
- `guest` routes, `signed` routes, and routes with any custom middleware Plumbline doesn't recognise.
- Webhook, payment-callback and auth-flow paths (`webhooks/*`, `stripe/*`, `login`, `password/*`, `unsubscribe`...).
- Routes keyed by a token, hash or code (`/invites/{token}`).
- Actions that check the user themselves (`auth()`, `Auth::`, `Gate`, `abort()`...).
- Controllers that apply `auth` through `HasMiddleware::middleware()` or `$this->middleware()`.
