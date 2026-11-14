# CRYPTO-001: Weak hashing, randomness or comparison for secrets

**Severity:** High, Medium or Low · **CWE-327, CWE-330, CWE-208**

## What it finds
These checks work from variable and key names, so they only fire where the name says it holds a secret:

| Severity | Pattern |
|---|---|
| High | `md5`/`sha1`/`hash('sha256', ...)` applied to a password |
| Medium | `rand`, `mt_rand`, `uniqid`, `str_shuffle`, `time()`... used to generate a token, OTP, PIN, API key or verification code |
| Low | `==`/`===` comparing a token, signature or HMAC, which leaks timing. Use `hash_equals()`. |

## How to fix
- Passwords: `Hash::make()`.
- Secrets: `Str::random(40)`, `random_int()` or `random_bytes()`.
- Comparisons: `hash_equals($known, $given)`.

## Not reported
- `md5($user->email)` (Gravatar) and cache keys.
- `rand()` for values that aren't secret, like colours.
- Comparisons against literals or `null`.
- Metadata names like `token_expires_at` or `password_length`.
