# Contributing to Plumbline

Thanks for helping. Plumbline makes one promise: **a finding should be worth a developer's
time.** Every change is judged against that.

## Setup

```bash
git clone https://github.com/Diddyy/Plumbline
cd plumbline
composer install
composer test      # Pest
composer analyse   # PHPStan
```

Try it on any Laravel app:

```bash
php bin/plumbline scan /path/to/app
```

## Reporting a false positive

False positives are the bugs we care about most. Use the **False positive** issue template
and include the smallest code that triggers it. Please trim real application code down
first; don't paste it whole.

## Adding or changing a rule

A rule is a class plus fixtures. Nothing merges without fixtures.

1. Add the rule in `src/Rules/`.
   - It implements `TaintRule` if it asks whether user input reaches a sink. The engine walks
     every function once, in source order, and gives you each node with the current taint state.
   - It implements `ProjectRule` if it inspects config, routes, Blade or models.
2. Register it in `Plumbline::defaultRules()`.
3. Add fixtures:
   - `tests/Fixtures/<RULE-ID>/vulnerable/`: realistic Laravel code. Put `// expect: RULE-ID`
     at the end of every line that must be reported (`{{-- expect: RULE-ID --}}` in Blade,
     `# expect: RULE-ID` in .env files). The test fails if a marked line isn't reported, **or
     if any unmarked line is**.
   - `tests/Fixtures/<RULE-ID>/safe/`: the patterns people use to do it correctly. This
     fixture must produce zero findings.
4. Add `docs/rules/<RULE-ID>.md`: what it finds, why it matters, how to fix it, and what it
   deliberately ignores.

### Rule design guidelines

- **When in doubt, stay quiet.** Unknown functions return clean values. Unknown route middleware
  might be an access check, so access rules skip those routes.
- **Explain the flow.** Messages name the source (`$request->input('sort')`) and the sink,
  and say how to fix it.
- **Severity follows exploitability.** Use Critical/High only when the flow alone is enough to
  exploit. Use Low for "this deserves a look".
- Stay intra-procedural unless you have fixtures proving that a wider analysis stays precise.

## Pull requests

- Keep each PR to one rule or one behaviour change.
- `composer test` and `composer analyse` must pass.
- Add a line to `CHANGELOG.md` under *Unreleased*.
