# SQLI-001: User input reaches raw SQL

**Severity:** Critical · **CWE-89**

## What it finds
Request data concatenated or interpolated into SQL passed to:
- `DB::raw()`, `DB::select()`, `DB::statement()` and `DB::connection()->select()`
- `new Expression()`
- PDO `query()`/`exec()`
- any `*Raw()` builder method (`whereRaw`, `orderByRaw`, `selectRaw`, `havingRaw`, `groupByRaw`...)

"User input" means any of these:
- `$request->input()` and its relatives, `request()`, `$_GET`/`$_POST`
- untyped or `string` route parameters
- Livewire public properties and action arguments

```php
$sort = $request->query('sort');
Post::orderByRaw($sort.' desc')->get();                 // reported

DB::select("select * from users where name = '$name'"); // reported
```

## How to fix
Pass values as bindings. Identifiers (columns, sort directions) can't be bound, so check them against an allowlist:

```php
DB::select('select * from users where name = ?', [$name]);

$sort = in_array($sort, ['name', 'created_at'], true) ? $sort : 'id';
Post::orderByRaw($sort.' desc')->get();
```

## Not reported
- Values passed as bindings (the second argument).
- Values cast to `int`/`float`/`bool`, or read with `$request->integer()`, `->boolean()`, `->date()` or `->enum()`.
- Keys validated as `integer`, `numeric`, `boolean`, `uuid`, `ulid`, `date`, `in:`, `Rule::in()`, `Rule::enum()` or `exists:`.
  Validation through `$request->validate()`, `Validator::make()` and a FormRequest's `rules()` all count.
- Variables checked with `in_array()` before use, and values picked by a `match` expression.
  Both guard styles count: `if (! in_array(...)) abort(...)` and `abort_unless(in_array(...))`.
- `#[Locked]` Livewire properties, and Livewire properties typed `int`.
