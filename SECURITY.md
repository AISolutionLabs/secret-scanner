# Security policy

## Reporting a vulnerability

Please report vulnerabilities **privately** through
[GitHub Security Advisories](https://github.com/AISolutionLabs/secret-scanner/security/advisories/new).
Do not open a public issue.

Include the version (`secretscan version`), a description, and a
reproduction that contains **no real secrets**. We aim to acknowledge within
3 business days and to agree a disclosure timeline with you.

## In scope

- Secrets leaking through secretscan itself: unredacted output, report or
  patch files with weak permissions, verification sending a secret to the
  wrong host.
- Ways to bypass the hooks or a scan that a user would reasonably expect to
  hold (e.g. a crafted diff that hides added lines).
- Code execution or path traversal from scanned content, configs or diffs.

Detection gaps (a token format we don't catch) are not vulnerabilities.
Please file them as "Missed secret" issues.

## Supported versions

Security fixes go into the latest release.
