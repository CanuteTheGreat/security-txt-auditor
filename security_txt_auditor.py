#!/usr/bin/env python3
"""
security-txt-auditor -- free, zero-dependency tool from Errant Solutions
(https://errant.solutions)

Audits a domain's robots.txt and security.txt (RFC 9116) for common
misconfigurations.

  robots.txt:
    - missing (informational), present but empty, unexpected HTTP status
    - references a Sitemap that doesn't answer 200
    - disallows "/" for every crawler (often a leftover staging rule)

  security.txt (/.well-known/security.txt, falling back to legacy /security.txt):
    - missing entirely (no disclosed vulnerability-reporting contact)
    - served with a Content-Type other than text/plain, or without charset=utf-8
    - Contact: missing, or not a mailto:/https:/tel: URI; email-only/web-only notes
    - Expires: missing, more than once, not RFC 3339 with a timezone, already
      passed, or more than a year out (RFC 9116 recommends less than a year)
    - Canonical: missing (informational) or none of them matches the URL the file
      was actually served from
    - Encryption/Policy/Acknowledgments/Hiring/Canonical https:// URLs that don't
      answer 200, or http:// URLs (must be https)
    - OpenPGP cleartext signature present (reported; the signature itself is not
      verified) or absent (informational); fields are read from the signed part
    - unknown fields (informational)
    - only found at the legacy /security.txt location (informational)

Usage:
    security-txt-auditor [--json] [--fail-on warn|info|never] example.com [example2.com ...]

Exit codes: 0 = nothing at or above --fail-on (default: warn), 1 = at least one
such finding, 2 = a target could not be reached (and nothing else failed the
gate) or usage error. No API keys, no third-party services: plain HTTPS requests
to the target's own web server.
"""

__version__ = "1.2.0"

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

UA = "Mozilla/5.0 (compatible; security-txt-auditor/%s; +https://errant.solutions)" % __version__
TIMEOUT = 10
LEVELS = ("ERROR", "WARN", "INFO", "OK")
GATE = {"warn": ("ERROR", "WARN"), "info": ("ERROR", "WARN", "INFO"), "never": ()}
KNOWN_FIELDS = {"acknowledgments", "canonical", "contact", "encryption", "expires", "hiring", "policy",
                "preferred-languages", "csaf"}
URL_FIELDS = ("canonical", "encryption", "policy", "acknowledgments", "hiring")


class Response:
    def __init__(self, code, body="", headers=None, url=None, error=None):
        self.code, self.body, self.headers, self.url, self.error = code, body, headers or {}, url, error


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return Response(resp.getcode(), resp.read().decode("utf-8", errors="replace"),
                            {k.lower(): v for k, v in resp.headers.items()}, resp.geturl())
    except urllib.error.HTTPError as e:
        return Response(e.code, "", {k.lower(): v for k, v in (e.headers or {}).items()}, url)
    except Exception as e:
        return Response(None, error=str(getattr(e, "reason", e)))


def add(findings, category, level, message):
    findings.append({"category": category, "level": level, "message": message})


def check_robots(domain, findings):
    r = fetch(f"https://{domain}/robots.txt")
    if r.code is None:
        add(findings, "robots.txt", "ERROR", f"could not connect ({r.error})")
        return False
    if r.code == 404:
        add(findings, "robots.txt", "INFO", "not present (not required, but common)")
        return True
    if r.code != 200:
        add(findings, "robots.txt", "WARN", f"unexpected HTTP {r.code}")
        return True
    if not r.body.strip():
        add(findings, "robots.txt", "WARN", "present but empty")
        return True

    # RFC 9309: consecutive User-agent lines open one group; its rules apply to every agent named
    agents, in_rules, disallow_all, sitemaps = set(), False, False, []
    for raw in r.body.splitlines():
        line = raw.split("#", 1)[0].strip()
        low = line.lower()
        if low.startswith("user-agent:"):
            if in_rules:
                agents, in_rules = set(), False
            agents.add(line.split(":", 1)[1].strip())
        elif low.startswith("sitemap:"):
            sitemaps.append(line.split(":", 1)[1].strip())
        elif low.startswith(("disallow:", "allow:")):
            in_rules = True
            if low.startswith("disallow:") and line.split(":", 1)[1].strip() == "/" and ("*" in agents or not agents):
                disallow_all = True

    if disallow_all:
        add(findings, "robots.txt", "WARN", "contains 'Disallow: /' for every crawler - blocks the whole site "
                                            "(verify this is intentional, not a leftover staging rule)")
    else:
        add(findings, "robots.txt", "OK", "present, does not block all crawlers")
    for sm in sitemaps:
        code = fetch(sm).code
        if code == 200:
            add(findings, "robots.txt", "OK", f"referenced sitemap reachable: {sm}")
        else:
            add(findings, "robots.txt", "WARN", f"referenced sitemap returns HTTP {code}: {sm}")
    return True


SIGNED_RE = re.compile(r"-----BEGIN PGP SIGNED MESSAGE-----\r?\n(?:Hash:[^\n]*\r?\n)*\r?\n(.*?)"
                       r"\r?\n-----BEGIN PGP SIGNATURE-----.*?-----END PGP SIGNATURE-----", re.S)


def parse_security_txt(body):
    """Returns (fields, signed). Fields map lower-cased names to lists of values."""
    m = SIGNED_RE.search(body)
    signed = bool(m)
    if m:
        # dash-escaped lines (RFC 4880 7.1) start with "- "
        body = "\n".join(l[2:] if l.startswith("- ") else l for l in m.group(1).splitlines())
    fields = {}
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            k, v = line.split(":", 1)
            fields.setdefault(k.strip().lower(), []).append(v.strip())
    return fields, signed


RFC3339_RE = re.compile(r"(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(?:([Zz])|([+-])(\d{2}):(\d{2}))")


def parse_expires(raw):
    """RFC 3339 section 5.6 date-time (what RFC 9116 requires), parsed the same on every Python:
    datetime.fromisoformat accepts other ISO 8601 forms on 3.11+ and rejects valid ones before."""
    m = RFC3339_RE.fullmatch(raw.strip())
    if not m:
        raise ValueError("not an RFC 3339 date-time")
    y, mo, d, h, mi, s = (int(x) for x in m.groups()[:6])
    if m.group(8):
        tz = timezone.utc
    else:
        off = timedelta(hours=int(m.group(10)), minutes=int(m.group(11)))
        if off >= timedelta(hours=24):
            raise ValueError("bad offset")
        tz = timezone(off if m.group(9) == "+" else -off)
    return datetime(y, mo, d, h, mi, min(s, 59), tzinfo=tz) + timedelta(seconds=max(s - 59, 0))


def check_security_txt(domain, findings, check_urls=True):
    preferred = f"https://{domain}/.well-known/security.txt"
    found = None
    for url in (preferred, f"https://{domain}/security.txt"):
        r = fetch(url)
        if r.code == 200 and r.body.strip():
            found = (url, r)
            break
    if not found:
        add(findings, "security.txt", "WARN", "not present at either standard location - no disclosed "
                                              "vulnerability-reporting contact (RFC 9116)")
        return
    url, r = found
    add(findings, "security.txt", "OK", f"found at {url}")
    if url != preferred:
        add(findings, "security.txt", "INFO", "only found at legacy /security.txt, not the RFC 9116-preferred "
                                              "/.well-known/security.txt - consider adding both (a redirect is fine)")

    ctype = r.headers.get("content-type", "")
    if ctype.split(";")[0].strip().lower() != "text/plain":
        add(findings, "security.txt", "WARN", f"served as '{ctype or '(no Content-Type)'}' - RFC 9116 requires text/plain")
    elif "charset=utf-8" not in ctype.lower().replace(" ", "").replace('"', ""):
        add(findings, "security.txt", "INFO", f"Content-Type '{ctype}' has no charset=utf-8 (RFC 9116 asks for it)")

    fields, signed = parse_security_txt(r.body)
    if signed:
        add(findings, "security.txt", "OK", "OpenPGP cleartext-signed (signature not verified by this tool)")
    else:
        add(findings, "security.txt", "INFO", "not digitally signed (RFC 9116 recommends an OpenPGP cleartext signature)")

    contacts = fields.get("contact")
    if not contacts:
        add(findings, "security.txt", "WARN", "missing required 'Contact:' field")
    else:
        add(findings, "security.txt", "OK", f"Contact: {', '.join(contacts)}")
        schemes = {c.split(":", 1)[0].lower() for c in contacts if ":" in c}
        bad = [c for c in contacts if c.split(":", 1)[0].lower() not in ("mailto", "https", "tel")]
        if bad:
            add(findings, "security.txt", "WARN",
                f"Contact value(s) not a mailto:/https:/tel: URI as RFC 9116 requires: {', '.join(bad)}")
        if "mailto" in schemes and "https" not in schemes:
            add(findings, "security.txt", "INFO", "Contact is email-only -- consider also listing an https:// reporting page/form")
        elif "https" in schemes and "mailto" not in schemes:
            add(findings, "security.txt", "INFO", "Contact is web-only -- consider also listing a mailto: address")

    expires = fields.get("expires")
    if not expires:
        add(findings, "security.txt", "WARN", "missing required 'Expires:' field")
    else:
        if len(expires) > 1:
            add(findings, "security.txt", "WARN", f"'Expires:' appears {len(expires)} times (RFC 9116: exactly once)")
        raw = expires[0]
        try:
            exp = parse_expires(raw)
        except ValueError:
            add(findings, "security.txt", "WARN", "Expires field present but not an RFC 3339 date-time with a "
                                                  f"timezone (e.g. 2027-01-01T00:00:00Z): {raw}")
        else:
            now = datetime.now(timezone.utc)
            if exp < now:
                add(findings, "security.txt", "WARN",
                    f"Expires date has PASSED ({raw}) - file looks abandoned to a researcher, refresh it")
            elif exp > now + timedelta(days=366):
                add(findings, "security.txt", "WARN",
                    f"Expires: {raw} is more than a year out (RFC 9116 recommends under a year to avoid staleness)")
            else:
                add(findings, "security.txt", "OK", f"Expires: {raw} (not yet expired, under a year out)")

    canon = fields.get("canonical", [])
    if not canon:
        add(findings, "security.txt", "INFO", "no 'Canonical:' field (recommended, especially for a signed file)")
    elif url not in canon and (r.url or url) not in canon:
        add(findings, "security.txt", "WARN", f"none of the Canonical URLs ({', '.join(canon)}) is the URL it was served from ({url})")
    else:
        add(findings, "security.txt", "OK", f"Canonical matches {url}")

    for name in URL_FIELDS:
        for value in fields.get(name, []):
            scheme = value.split(":", 1)[0].lower()
            if scheme == "http":
                add(findings, "security.txt", "WARN", f"{name.title()}: {value} uses http:// (RFC 9116 requires https)")
            elif scheme == "https" and check_urls and value not in (url, r.url):
                code = fetch(value).code
                if code != 200:
                    add(findings, "security.txt", "WARN", f"{name.title()}: {value} answers HTTP {code}")
                else:
                    add(findings, "security.txt", "OK", f"{name.title()}: {value} reachable")

    unknown = sorted(k for k in fields if k not in KNOWN_FIELDS)
    if unknown:
        add(findings, "security.txt", "INFO", f"unknown field(s): {', '.join(unknown)}")


def audit(domain, check_urls=True):
    findings = []
    if check_robots(domain, findings):
        check_security_txt(domain, findings, check_urls)
    else:
        add(findings, "security.txt", "ERROR", "skipped: host unreachable")
    return findings


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="security-txt-auditor",
        description="Audit a domain's robots.txt and security.txt (RFC 9116) for common misconfigurations.",
        epilog="Exit codes: 0 clean, 1 findings at/above --fail-on, 2 a target was unreachable or bad usage. "
               "Example: security-txt-auditor example.com example.org")
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    parser.add_argument("--json", action="store_true", help="machine-readable JSON output")
    parser.add_argument("--fail-on", choices=sorted(GATE), default="warn",
                        help="lowest level that makes the exit code 1 (default: warn)")
    parser.add_argument("--no-url-checks", action="store_true",
                        help="don't fetch the Policy/Encryption/Acknowledgments/Hiring/Canonical URLs")
    parser.add_argument("domains", nargs="+", metavar="domain",
                        help="domain or URL to audit (scheme and trailing slash are stripped)")
    args = parser.parse_args(argv)

    results = []
    for domain in args.domains:
        domain = re.sub(r"^https?://", "", domain.strip()).rstrip("/")
        results.append({"domain": domain, "findings": audit(domain, not args.no_url_checks)})

    gate = GATE[args.fail_on]
    failed = any(f["level"] in gate and f["level"] != "ERROR" for r in results for f in r["findings"])
    errored = any(f["level"] == "ERROR" for r in results for f in r["findings"])
    code = 1 if failed else (2 if errored else 0)

    if args.json:
        print(json.dumps({"version": __version__, "fail_on": args.fail_on, "exit_code": code, "results": results},
                         indent=2))
    else:
        for r in results:
            print(f"\n=== {r['domain']} ===")
            for f in r["findings"]:
                print(f"  [{f['level']:5s}] {f['category']}: {f['message']}")
        if failed:
            print(f"\nFAIL: findings at or above {args.fail_on.upper()} (exit 1)")
    return code


if __name__ == "__main__":
    sys.exit(main())
