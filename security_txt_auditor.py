#!/usr/bin/env python3
"""
security-txt-auditor.py — free, zero-dependency tool from Errant Solutions
(https://errant.solutions)

Audits a domain's robots.txt and security.txt (RFC 9116) for common
misconfigurations:

  robots.txt:
    - missing entirely
    - present but empty (parser errors / accidental truncation)
    - references a Sitemap that 404s
    - accidentally disallows "/" (blocks all crawlers - often a copy-paste
      mistake left over from a staging config)

  security.txt (checked at both /.well-known/security.txt [preferred, RFC 9116]
  and /security.txt [legacy fallback location]):
    - missing entirely (no disclosed vulnerability-reporting contact)
    - missing required "Contact:" field
    - missing required "Expires:" field
    - Expires date has already passed (stale file - looks abandoned to a
      researcher deciding whether to bother reporting something)
    - Contact field is a mailto: link with no matching web fallback, or vice
      versa (informational, not a failure)

Usage:
    python3 security_txt_auditor.py example.com [example2.com ...]

No API keys, no signup, no third-party services - pure stdlib HTTP requests
to the target's own web server. Exit code is 0 always (this is a reporting
tool, not a CI gate); 2 on a usage error (e.g. no domain given).
"""

import argparse
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone


UA = "Mozilla/5.0 (compatible; security-txt-auditor/1.0; +https://errant.solutions)"
TIMEOUT = 10


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            code = resp.getcode()
            body = resp.read().decode("utf-8", errors="replace")
            return code, body
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception as e:
        return None, str(e)


def check_robots(domain, findings):
    url = f"https://{domain}/robots.txt"
    code, body = fetch(url)
    if code is None:
        findings.append(("robots.txt", "ERROR", f"could not connect ({body})"))
        return
    if code == 404:
        findings.append(("robots.txt", "INFO", "not present (not required, but common)"))
        return
    if code != 200:
        findings.append(("robots.txt", "WARN", f"unexpected HTTP {code}"))
        return
    if not body.strip():
        findings.append(("robots.txt", "WARN", "present but empty"))
        return

    lines = [l.strip() for l in body.splitlines()]
    disallow_all = False
    sitemaps = []
    for l in lines:
        low = l.lower()
        if low.startswith("disallow:"):
            val = l.split(":", 1)[1].strip()
            if val == "/":
                disallow_all = True
        if low.startswith("sitemap:"):
            sm = l.split(":", 1)[1].strip()
            sitemaps.append(sm)

    if disallow_all:
        findings.append(("robots.txt", "WARN",
                          "contains 'Disallow: /' - blocks ALL crawlers site-wide "
                          "(verify this is intentional, not a leftover staging rule)"))
    else:
        findings.append(("robots.txt", "OK", "present, does not block all crawlers"))

    for sm in sitemaps:
        scode, _ = fetch(sm)
        if scode == 200:
            findings.append(("robots.txt", "OK", f"referenced sitemap reachable: {sm}"))
        else:
            findings.append(("robots.txt", "WARN",
                              f"referenced sitemap returns HTTP {scode}: {sm}"))


def parse_security_txt(body):
    fields = {}
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            k, v = line.split(":", 1)
            fields.setdefault(k.strip().lower(), []).append(v.strip())
    return fields


def check_security_txt(domain, findings):
    locations = [
        f"https://{domain}/.well-known/security.txt",
        f"https://{domain}/security.txt",
    ]
    found_at = None
    body = None
    for url in locations:
        code, b = fetch(url)
        if code == 200 and b.strip():
            found_at = url
            body = b
            break

    if not found_at:
        findings.append(("security.txt", "INFO",
                          "not present at either standard location - no disclosed "
                          "vulnerability-reporting contact (RFC 9116 recommends one)"))
        return

    findings.append(("security.txt", "OK", f"found at {found_at}"))
    fields = parse_security_txt(body)

    if "contact" not in fields:
        findings.append(("security.txt", "WARN", "missing required 'Contact:' field"))
    else:
        contacts = fields["contact"]
        findings.append(("security.txt", "OK", f"Contact: {', '.join(contacts)}"))
        schemes = {c.split(":", 1)[0].lower() for c in contacts if ":" in c}
        bad = [c for c in contacts if c.split(":", 1)[0].lower() not in ("mailto", "https", "tel")]
        if bad:
            findings.append(("security.txt", "WARN",
                              f"Contact value(s) not a mailto:/https:/tel: URI as RFC 9116 requires: {', '.join(bad)}"))
        if "mailto" in schemes and "https" not in schemes:
            findings.append(("security.txt", "INFO",
                              "Contact is email-only -- consider also listing an https:// reporting page/form"))
        elif "https" in schemes and "mailto" not in schemes:
            findings.append(("security.txt", "INFO",
                              "Contact is web-only -- consider also listing a mailto: address"))

    if "expires" not in fields:
        findings.append(("security.txt", "WARN", "missing required 'Expires:' field"))
    else:
        exp_raw = fields["expires"][0]
        try:
            exp_dt = datetime.fromisoformat(exp_raw.replace("Z", "+00:00"))
            if exp_dt.tzinfo is None:
                raise ValueError("no timezone")
            now = datetime.now(timezone.utc)
            if exp_dt < now:
                findings.append(("security.txt", "WARN",
                                  f"Expires date has PASSED ({exp_raw}) - file looks "
                                  "abandoned to a researcher, refresh it"))
            else:
                findings.append(("security.txt", "OK", f"Expires: {exp_raw} (not yet expired)"))
        except Exception:
            findings.append(("security.txt", "WARN",
                              f"Expires field present but not an RFC 3339 date-time with a timezone "
                              f"(e.g. 2027-01-01T00:00:00Z): {exp_raw}"))

    if found_at.endswith("/security.txt") and found_at != f"https://{domain}/.well-known/security.txt":
        findings.append(("security.txt", "INFO",
                          "only found at legacy /security.txt, not the RFC 9116-preferred "
                          "/.well-known/security.txt - consider adding both (a redirect is fine)"))


def audit(domain):
    print(f"\n=== {domain} ===")
    findings = []
    check_robots(domain, findings)
    check_security_txt(domain, findings)
    for category, level, msg in findings:
        print(f"  [{level:5s}] {category}: {msg}")
    return findings


def main():
    parser = argparse.ArgumentParser(
        prog="security_txt_auditor.py",
        description="Audit a domain's robots.txt and security.txt (RFC 9116) "
                    "for common misconfigurations.",
        epilog="Example: python3 security_txt_auditor.py example.com example.org",
    )
    parser.add_argument("domains", nargs="+", metavar="domain",
                        help="domain or URL to audit (scheme and trailing slash are stripped)")
    args = parser.parse_args()
    for domain in args.domains:
        domain = domain.strip().replace("https://", "").replace("http://", "").rstrip("/")
        audit(domain)


if __name__ == "__main__":
    main()
