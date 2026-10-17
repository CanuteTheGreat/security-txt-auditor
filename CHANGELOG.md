# Changelog

All notable changes. Versions are git tags; each tag has a Forgejo release with checksums.

## 1.2.1 - 2026-10-17

- robots.txt groups follow RFC 9309: `User-agent: *` followed by another `User-agent:` line and `Disallow: /` blocks every crawler and is now flagged (only the last agent of a group was considered).
- `Expires:` is parsed with the RFC 3339 grammar on every Python version: Python 3.11+ used to accept non-RFC 3339 forms (`20270101T000000Z`, a space instead of `T`) and older versions rejected valid ones (`.5Z` fractions).
- Tests: accuracy suite (clean real-world-style files incl. signed/CRLF/offsets, 19 known-bad cases, Expires grammar table, 200 random robots.txt files against urllib.robotparser), mutation testing (nightly), claims ledger.

## 1.2.0 - 2026-10-16

- **`--json`** output and a real **CI gate**: exit 1 when a finding is at or above `--fail-on`
  (default `warn`), 2 when a target can't be reached. It used to exit 0 on every run.
- A missing security.txt is now a WARN (was INFO).
- New RFC 9116 checks: Content-Type must be `text/plain` (charset note), `Expires` more than a year out
  or repeated, `Canonical` missing or not matching the served URL, `http://` or unreachable
  Policy/Encryption/Acknowledgments/Hiring/Canonical links (`--no-url-checks` to skip), OpenPGP cleartext
  signatures detected and the signed body parsed, unknown fields reported.
- robots.txt: `Disallow: /` is only flagged when it applies to every crawler (`User-agent: *`).
- Installable as a package: `pipx install git+https://git.canutethegreat.com/CanuteTheGreat/security-txt-auditor.git`
  puts a `security-txt-auditor` command on PATH (pyproject.toml, MIT license metadata).
- `--version` flag.
- Exit codes follow the shared convention: 0 = clean, 1 = findings at/above the gate, 2 = error or bad usage.
- Every tag now publishes a Forgejo release with this changelog, the wheel, the sdist and SHA256SUMS.
- CI installs the package with pip in a clean venv and checks `--version`/`--help` on every push.

## 1.1.0 - 2026-10-16

- Check Contact URI schemes and timezone-less Expires as documented, argparse CLI, add CI tests

## 1.0.0 - 2026-09-16

- First public release.
