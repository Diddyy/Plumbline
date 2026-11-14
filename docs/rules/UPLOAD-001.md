# UPLOAD-001: Upload stored under a client-chosen file name

**Severity:** Medium (High when stored publicly) · **CWE-434**

## What it finds
`storeAs()`, `storePubliclyAs()`, `putFileAs()` or `$file->move()` using `getClientOriginalName()`,
`getClientOriginalExtension()` or request input as the stored name.

The client then picks the extension. In a web-served directory, `shell.php` can be executed and `page.html`
can be served as active content.

## How to fix
Use any of these:
- `$file->store('avatars')` (random name)
- `$file->hashName()`
- `Str::uuid().'.'.$file->extension()` (the extension is guessed from the file's content)

## Not reported
- Names that end in a server-chosen extension (`.'.'.$file->extension()`, `'.jpg'`).
- `move()` methods that have nothing to do with uploads.
