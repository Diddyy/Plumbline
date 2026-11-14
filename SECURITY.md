# Security policy

## Reporting a vulnerability in Plumbline itself

Please use GitHub's private vulnerability reporting ("Report a vulnerability" under the
Security tab). Don't open a public issue. You should get a reply within 7 days.

Plumbline only reads source files. It never executes or boots the code it scans. A bug
that makes Plumbline run, include or evaluate scanned code would count as a vulnerability.

## Found a vulnerability in someone else's app with Plumbline?

Report it privately to the project's maintainers, through their `SECURITY.md` or GitHub
private advisories. Give them reasonable time to fix it before saying anything publicly.
Please don't post real-world findings in Plumbline issues.

## False negatives

Plumbline missing a vulnerability isn't a security issue in Plumbline. Please open a normal
issue with a minimal example, ideally as a new fixture (see CONTRIBUTING.md).
