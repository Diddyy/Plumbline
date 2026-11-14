# AUTHZ-001: Route changes a URL-chosen record without an authorization check

**Severity:** High · **CWE-639** (insecure direct object reference)

## What it finds
A route behind authentication that updates or deletes a model it receives through route-model binding
(`/posts/{post}`), with no sign that anyone checks whether the user may touch *that* record. Any
signed-in user can change the ID in the URL to edit or delete other people's data.

```php
Route::middleware('auth')->delete('/posts/{post}', [PostController::class, 'destroy']);

public function destroy(Post $post)
{
    $post->delete();   // reported
}
```

## How to fix
Add a policy check with any of these:
- `$this->authorize('delete', $post)`
- `Gate::authorize(...)`
- `->can('delete', 'post')` on the route
- `authorizeResource()` in the controller

## Not reported (any authorization evidence counts)
- `can:`, `role:` or `permission:` middleware, or **any custom route middleware** Plumbline doesn't
  recognise (it might be an access check).
- `$this->authorize()`, `Gate::*`, `->can()`/`->cannot()`, `abort_if`/`abort_unless`/`abort()`, or
  `throw new AuthorizationException`.
- Ownership comparisons against `auth()` or `$request->user()`.
- A FormRequest whose `authorize()` does more than `return true;`.
- `authorizeResource()` in the controller constructor, or `#[Can]`/`#[Authorize]`/`#[Middleware]` attributes.
- Models with a global scope, `#[ScopedBy]`, or a tenancy/team trait. Their binding is already scoped.
- Routes in files whose loading context can't be worked out statically.

## Limitations
Plumbline can't tell whether every authenticated user is meant to be an admin, which some internal tools do.
If that's your app, suppress the rule with a reason or use a baseline.
