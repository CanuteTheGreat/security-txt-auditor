# security-txt-auditor

Free, zero-dependency (Python stdlib only) tool from [Errant Solutions](https://errant.solutions).

Audits a domain's `robots.txt` and `security.txt` (RFC 9116) for common misconfigurations:

**robots.txt**
- missing entirely
- present but empty
- references a `Sitemap:` that 404s
- accidentally contains `Disallow: /` (blocks all crawlers site-wide — often a leftover
  staging config)

**security.txt** (checked at both `/.well-known/security.txt` — the RFC 9116-preferred
location — and the legacy `/security.txt`)
- missing entirely (no disclosed vulnerability-reporting contact)
- missing the required `Contact:` field
- missing the required `Expires:` field
- `Expires:` date has already passed (a stale file looks abandoned to a security
  researcher deciding whether it's worth reporting something to you)

## Usage

```
python3 security_txt_auditor.py example.com [example2.com ...]
```

No API keys, no signup, no third-party services involved — it only talks to the
target's own web server. Source is MIT-licensed; read it before you run it against
anything you don't own.

## Pay what you want

If this saved you time: https://errant.solutions (payment link on the site).
