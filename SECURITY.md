# Security Policy

## Reporting a vulnerability

Please report security problems **privately**, not in a public issue:

- Use GitHub's **Report a vulnerability** button on the
  [Security tab](https://github.com/tomtom215/vps-audit/security/advisories/new).

Include the version (`./vps-audit.sh --version`), your distribution, and the
smallest input that reproduces the problem. This is a volunteer-maintained
project: reports are handled on a best-effort basis, without a fixed response
time.

## What counts as a vulnerability here

`vps-audit.sh` runs as **root** and reads files that other users can influence
(usernames, home directories, configuration, log lines). These are in scope:

- Anything that makes the script **execute attacker-controlled input** (command
  injection through a filename, username, config value or log line).
- **Terminal escape injection**: system-supplied text reaching the operator's
  terminal or the report files unfiltered.
- **Unsafe handling of its own files**: predictable or world-readable
  temporary/report files, following attacker-planted symlinks while root,
  sourcing a configuration file that a non-root user could have modified.
- A way to make the script **change** the system. It is designed to be
  read-only.

These are ordinary bugs, not vulnerabilities: a check that gives a wrong
verdict (please open a "Wrong result" issue), or a finding about the server
being audited.

## Supported versions

Only the latest release receives fixes.

## Verifying a download

Release assets are published with a `SHA256SUMS` file and a build-provenance
attestation:

```bash
sha256sum -c SHA256SUMS
gh attestation verify vps-audit.sh --repo tomtom215/vps-audit
```

Download from the release page (`releases/download/<tag>/vps-audit.sh`), not from
`raw.githubusercontent.com`; the attestation covers the release asset.
