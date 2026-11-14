# DESER-001: User input is unserialized

**Severity:** High · **CWE-502**

## What it finds
`unserialize()` called on request data without restricting classes, including after `base64_decode()`.
An attacker can instantiate any autoloadable class. Laravel apps ship gadget chains that turn this into
remote code execution.

## How to fix
Use JSON: `json_decode($request->input('state'), true)`. If you really need `unserialize()`, pass
`['allowed_classes' => false]` or an explicit allowlist.

## Not reported
- `unserialize($data, ['allowed_classes' => false])`, or an allowlist array.
- Data that doesn't come from the request (cache, database).
