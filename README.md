# security-txt-auditor

Free, zero-dependency (Python stdlib only) tool from [Errant Solutions](https://errant.solutions).

Audits a domain's `robots.txt` and `security.txt` (RFC 9116) for common misconfigurations:

**robots.txt**
- missing entirely
- present but empty
- references a `Sitemap:` that 404s
- accidentally contains `Disallow: /` (blocks all crawlers site-wide — often a leftover
  staging config)

**security.txt** (checked at `/.well-known/security.txt`, the RFC 9116 location, falling back
to the legacy `/security.txt`)
- missing entirely (WARN: no disclosed vulnerability-reporting contact)
- served as something other than `text/plain`, or without `charset=utf-8`
- missing `Contact:`, or values that aren't `mailto:` / `https:` / `tel:` URIs, plus a note
  when contact is email-only or web-only
- missing `Expires:`, repeated, not an RFC 3339 date-time with a timezone
  (e.g. `2027-01-01T00:00:00Z`), already passed, or more than a year out (RFC 9116
  recommends under a year)
- `Canonical:` missing (informational) or not matching the URL the file was served from
- `Policy:` / `Encryption:` / `Acknowledgments:` / `Hiring:` / `Canonical:` links that are
  `http://` or don't answer 200 (`--no-url-checks` skips fetching them)
- an OpenPGP cleartext signature is detected and the signed part is what gets parsed
  (the signature itself isn't verified); unsigned files get an informational note
- unknown fields, and a file only found at the legacy location (informational)

## Install

```sh
pipx install git+https://git.canutethegreat.com/CanuteTheGreat/security-txt-auditor.git        # latest release branch; puts `security-txt-auditor` on PATH
pipx install git+https://git.canutethegreat.com/CanuteTheGreat/security-txt-auditor.git@v1.2.0  # a pinned release
brew install canutethegreat/errant-tools/security-txt-auditor   # after: brew tap canutethegreat/errant-tools https://git.canutethegreat.com/CanuteTheGreat/homebrew-errant-tools
scoop install errant-tools/security-txt-auditor                 # after: scoop bucket add errant-tools https://git.canutethegreat.com/CanuteTheGreat/scoop-errant-tools
```

Or download the single file (stdlib-only Python 3.7+) and run it directly:
`curl -fsSLO https://errant.solutions/downloads/security_txt_auditor.py && python3 security_txt_auditor.py --help`.
Every [release](https://git.canutethegreat.com/CanuteTheGreat/security-txt-auditor/releases) has a changelog, the wheel, the sdist and a `SHA256SUMS` file.
Not on PyPI yet, so plain `pipx install security-txt-auditor` doesn't work until it's published there.

## Usage

```
security-txt-auditor example.com [example2.com ...]
security-txt-auditor --json example.com           # machine-readable
security-txt-auditor --fail-on info example.com   # strictest CI gate
```

Python 3.7+. Exit codes (same convention as every Errant Solutions tool):

| Code | Meaning |
|---|---|
| 0 | nothing at or above `--fail-on` (default `warn`; `info` and `never` also accepted) |
| 1 | at least one finding at or above `--fail-on` |
| 2 | a target couldn't be reached (and nothing else failed the gate), or bad usage |

No API keys, no signup, no third-party services involved: it only talks to the
target's own web server. Source is MIT-licensed; read it before you run it against
anything you don't own.

## Pay what you want

If this saved you time: https://errant.solutions (payment link on the site).
