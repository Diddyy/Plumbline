# MASS-001: Unfiltered request data written to a model

**Severity:** High · **CWE-915**

## What it finds
The whole request written to a model, when something makes that dangerous.

"The whole request" is `$request->all()`, `->except()`, `->input()` with no key, or
`array_merge($request->all(), ...)`. "Written" means `create`, `update`, `fill`, `forceFill`,
`forceCreate`, `firstOrCreate`, `updateOrCreate` or `new Model(...)`.

It is dangerous when any of these is true:
- The model has `$guarded = []`, or the app calls `Model::unguard()`.
- `forceFill()` or `forceCreate()` deliberately bypasses mass-assignment protection.
- The write goes through the query builder (`Post::where(...)->update($request->all())`), which ignores `$fillable`.
- `$fillable` contains attributes a user should never set, such as `is_admin`, `role`, `user_id`, `team_id`,
  `balance` or `email_verified_at`.

```php
// User::$fillable = ['name', 'email', 'password', 'is_admin']
$request->user()->update($request->all());   // reported: anyone can make themselves admin
```

## How to fix
Write only validated or named fields: `$request->validated()`, `$request->safe()->only([...])` or
`$request->only(['name', 'email'])`.

## Not reported
- Models whose `$fillable` lists only harmless attributes.
- `validated()`, `safe()`, `only([...])` and explicit arrays.
