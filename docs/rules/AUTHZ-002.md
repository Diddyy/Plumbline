# AUTHZ-002: Livewire action changes a client-chosen record without an authorization check

**Severity:** High · **CWE-639** (insecure direct object reference)

## What it finds
Every public method on a Livewire component is an endpoint. The browser can call it with any arguments
(`$wire.delete(42)` from the console), and set any public property that isn't `#[Locked]`. An action
that looks up a record from one of those values and changes it, without checking who is asking, lets
anyone who can load the component edit or delete any record.

```php
class PostTable extends Component
{
    public function delete($id)
    {
        Post::find($id)->delete();   // reported
    }
}
```

## How to fix
Authorize the record, or look it up through the current user:

```php
$post = Post::findOrFail($id);
$this->authorize('delete', $post);
$post->delete();

// or
auth()->user()->posts()->findOrFail($id)->delete();
```

## Not reported
- Lookups scoped to the current user (`auth()->user()->posts()->find($id)`, `->where('user_id', auth()->id())`).
- Any authorization evidence in the action: `$this->authorize()`, `Gate::*`, `->can()`,
  `abort_if`/`abort_unless`, ownership comparisons, or a same-class helper like `$this->ensureOwned($post)`.
- Records held in `#[Locked]` properties or model-typed properties (Livewire locks those).
- Models with a global scope, `#[ScopedBy]`, or a tenancy/team trait.
- Lifecycle hooks (`mount`, `render`, `boot*`, `hydrate*`, `updated*`...).
