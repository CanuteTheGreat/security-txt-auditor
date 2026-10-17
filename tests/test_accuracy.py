"""Detection accuracy for robots.txt and security.txt.

False negatives: known-bad files must produce the expected WARN. False positives: known-good
files modelled on real, well-maintained security.txt / robots.txt files must produce no WARN
or ERROR. Two independent references are used:
  * robots.txt "blocks every crawler" is checked against Python's own urllib.robotparser
    on a seeded random corpus of robots files (a generic crawler may not fetch "/");
  * Expires values are checked against the RFC 3339 section 5.6 date-time grammar,
    written out below from the RFC, so the verdict can't depend on the Python version.
"""
import datetime
import json
import os
import random
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.robotparser
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(os.path.dirname(HERE), "security_txt_auditor.py")
ROUTES = {}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        status, body, ctype = (ROUTES.get(self.path) or (404, "not found", "text/plain"))[:3]
        data = body.encode()
        self.send_response(status)
        if ctype:
            self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def setUpModule():
    global TMP, SERVER, HOST, CERT
    TMP = tempfile.mkdtemp()
    CERT, key = os.path.join(TMP, "cert.pem"), os.path.join(TMP, "key.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", CERT,
                    "-days", "2", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"],
                   check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    SERVER = HTTPServer(("127.0.0.1", 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, key)
    SERVER.socket = ctx.wrap_socket(SERVER.socket, server_side=True)
    HOST = "localhost:%d" % SERVER.server_address[1]
    threading.Thread(target=SERVER.serve_forever, daemon=True).start()


def tearDownModule():
    SERVER.shutdown()
    shutil.rmtree(TMP, ignore_errors=True)


def audit(routes, *args):
    ROUTES.clear()
    ROUTES.update({k: (v if isinstance(v, tuple) else (200, v, "text/plain; charset=utf-8")) for k, v in routes.items()})
    p = subprocess.run([sys.executable, TOOL, "--json"] + list(args) + [HOST], stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, universal_newlines=True, timeout=120,
                       env=dict(os.environ, SSL_CERT_FILE=CERT))
    return p.returncode, json.loads(p.stdout)["results"][0]["findings"]


def problems(findings, category=None):
    return [f["message"] for f in findings if f["level"] in ("WARN", "ERROR")
            and (category is None or f["category"] == category)]


def when(days):
    return (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def good_security_txt():
    # the shape of well-maintained real files (e.g. Google's, GitHub's): web + mail contacts,
    # expiry under a year, canonical, policy/acknowledgments/hiring/encryption all reachable
    return ("# Our security policy\n"
            "Contact: https://%(h)s/report\nContact: mailto:security@example.test\n"
            "Expires: %(exp)s\nEncryption: https://%(h)s/pgp-key.txt\n"
            "Acknowledgments: https://%(h)s/hall-of-fame\nPreferred-Languages: en, de\n"
            "Canonical: https://%(h)s/.well-known/security.txt\nPolicy: https://%(h)s/policy\n"
            "Hiring: https://%(h)s/jobs\n" % {"h": HOST, "exp": when(180)})


def good_routes():
    return {"/robots.txt": "User-agent: *\nDisallow: /admin/\nDisallow: /search\nAllow: /search/about\n"
                           "Sitemap: https://%s/sitemap.xml\n" % HOST,
            "/sitemap.xml": "<urlset/>", "/.well-known/security.txt": good_security_txt(),
            "/report": "form", "/pgp-key.txt": "key", "/hall-of-fame": "thanks", "/policy": "policy", "/jobs": "jobs"}


class TestFalsePositives(unittest.TestCase):
    def test_well_maintained_site_is_clean(self):
        code, f = audit(good_routes())
        self.assertEqual(problems(f), [])
        self.assertEqual(code, 0)

    def test_clean_variants(self):
        variants = {
            "signed file": lambda r: r.update({"/.well-known/security.txt":
                "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n" + good_security_txt() +
                "-----BEGIN PGP SIGNATURE-----\n\nwsBc...\n-----END PGP SIGNATURE-----\n"}),
            "CRLF line endings": lambda r: r.update({"/.well-known/security.txt": good_security_txt().replace("\n", "\r\n")}),
            "offset time zone": lambda r: r.update({"/.well-known/security.txt": good_security_txt().replace(
                when(180), when(180).replace("Z", "+02:00"))}),
            "fractional seconds": lambda r: r.update({"/.well-known/security.txt": good_security_txt().replace(
                when(180), when(180).replace("Z", ".123456789Z"))}),
            "charset with quotes and caps": lambda r: r.update({"/.well-known/security.txt":
                (200, good_security_txt(), 'text/plain; charset="UTF-8"')}),
            "no robots.txt": lambda r: r.pop("/robots.txt"),
            "robots blocks only some bots": lambda r: r.update({"/robots.txt":
                "User-agent: BadBot\nUser-agent: OtherBot\nDisallow: /\n\nUser-agent: *\nDisallow: /tmp/\n"}),
            "robots with comments and empty Disallow": lambda r: r.update({"/robots.txt":
                "# hello\nUser-agent: * # everyone\nDisallow:\n"}),
            "tel contact too": lambda r: r.update({"/.well-known/security.txt": good_security_txt() + "Contact: tel:+1-201-555-0123\n"}),
        }
        for name, change in variants.items():
            with self.subTest(variant=name):
                routes = good_routes()
                change(routes)
                code, f = audit(routes)
                self.assertEqual(problems(f), [], name)
                self.assertEqual(code, 0)


class TestFalseNegatives(unittest.TestCase):
    CASES = {
        "no security.txt": (lambda r: r.pop("/.well-known/security.txt"), "not present at either standard location"),
        "served as html": (lambda r: r.update({"/.well-known/security.txt": (200, good_security_txt(), "text/html")}),
                           "RFC 9116 requires text/plain"),
        "no Contact": (lambda r: r.update({"/.well-known/security.txt": re.sub(r"Contact: .*\n", "", good_security_txt())}),
                       "missing required 'Contact:' field"),
        "Contact is a bare address": (lambda r: r.update({"/.well-known/security.txt": good_security_txt().replace(
            "mailto:security@example.test", "security@example.test")}), "not a mailto:/https:/tel: URI"),
        "Contact over http": (lambda r: r.update({"/.well-known/security.txt": good_security_txt().replace(
            "Contact: https://", "Contact: http://")}), "not a mailto:/https:/tel: URI"),
        "no Expires": (lambda r: r.update({"/.well-known/security.txt": re.sub(r"Expires: .*\n", "", good_security_txt())}),
                       "missing required 'Expires:' field"),
        "expired": (lambda r: r.update({"/.well-known/security.txt": good_security_txt().replace(when(180), when(-1))}),
                    "Expires date has PASSED"),
        "Expires too far out": (lambda r: r.update({"/.well-known/security.txt": good_security_txt().replace(
            when(180), when(400))}), "more than a year out"),
        "two Expires": (lambda r: r.update({"/.well-known/security.txt": good_security_txt() + "Expires: %s\n" % when(100)}),
                        "appears 2 times"),
        "Expires without zone": (lambda r: r.update({"/.well-known/security.txt": good_security_txt().replace(
            when(180), when(180)[:-1])}), "not an RFC 3339 date-time"),
        "Canonical points elsewhere": (lambda r: r.update({"/.well-known/security.txt": good_security_txt().replace(
            "Canonical: https://%s/" % HOST, "Canonical: https://other.example/")}), "none of the Canonical URLs"),
        "Policy over http": (lambda r: r.update({"/.well-known/security.txt": good_security_txt().replace(
            "Policy: https://", "Policy: http://")}), "uses http://"),
        "Policy link broken": (lambda r: r.pop("/policy"), "Policy: https://"),
        "Encryption link broken": (lambda r: r.pop("/pgp-key.txt"), "Encryption: https://"),
        "robots blocks everything": (lambda r: r.update({"/robots.txt": "User-agent: *\nDisallow: /\n"}),
                                     "Disallow: /' for every crawler"),
        "robots group with * second": (lambda r: r.update({"/robots.txt": "User-agent: Googlebot\nUser-agent: *\nDisallow: /\n"}),
                                       "Disallow: /' for every crawler"),
        "robots group with * first": (lambda r: r.update({"/robots.txt": "User-agent: *\nUser-agent: Googlebot\nDisallow: /\n"}),
                                      "Disallow: /' for every crawler"),
        "robots empty": (lambda r: r.update({"/robots.txt": "\n"}), "present but empty"),
        "sitemap missing": (lambda r: r.pop("/sitemap.xml"), "referenced sitemap returns HTTP 404"),
    }

    def test_known_bad(self):
        for name, (change, needle) in self.CASES.items():
            with self.subTest(case=name):
                routes = good_routes()
                change(routes)
                code, f = audit(routes)
                self.assertTrue(any(needle in m for m in problems(f)), (needle, f))
                self.assertEqual(code, 1)


# RFC 3339 section 5.6 date-time, as RFC 9116 requires for Expires
RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$")


def rfc3339_ok(s):
    if not RFC3339.match(s):
        return False
    try:
        datetime.datetime(int(s[0:4]), int(s[5:7]), int(s[8:10]), int(s[11:13]), int(s[14:16]),
                          min(int(s[17:19]), 59))  # leap second 60 is valid RFC 3339
    except ValueError:
        return False
    return int(s[17:19]) <= 60


class TestExpiresGrammar(unittest.TestCase):
    """The same Expires value must get the same verdict on every Python version: valid exactly
    when it is an RFC 3339 date-time (Python 3.11+'s fromisoformat also takes ISO 8601 forms
    RFC 3339 doesn't allow, older Pythons reject valid ones)."""
    BASE = when(100)

    def test_grammar(self):
        d, t = self.BASE[:10], self.BASE[11:19]
        compact = d.replace("-", "") + "T" + t.replace(":", "")
        values = [self.BASE, d + "t" + t + "z", d + "T" + t + ".5Z", d + "T" + t + ".123456789+05:30",
                  d + "T" + t + "-00:00", d + "T" + t, d, d + " " + t + "Z", compact + "Z", d + "T" + t[:5] + "Z",
                  d + "T" + t + "+0530", d + "T" + t + "+05", d + "T" + t + "UTC", "next year",
                  d[:5] + "13" + d[7:] + "T" + t + "Z", d + "T25" + t[2:] + "Z"]
        for v in values:
            with self.subTest(expires=v):
                routes = good_routes()
                routes["/.well-known/security.txt"] = good_security_txt().replace(when(180), v)
                code, f = audit(routes)
                rejected = any("not an RFC 3339 date-time" in m for m in problems(f))
                self.assertEqual(rejected, not rfc3339_ok(v), (v, problems(f)))


class TestRobotsAgainstRobotparser(unittest.TestCase):
    """200 seeded random robots.txt files: the tool says 'blocks every crawler' exactly when
    urllib.robotparser says a generic crawler may not fetch '/'."""

    def test_random_corpus(self):
        rng = random.Random(9116)
        agents = ["*", "Googlebot", "Bingbot", "BadBot"]
        # no empty "Disallow:" lines: Python 3.7's robotparser reads one as "allow everything" for
        # the rest of the group, which RFC 9309 doesn't (an empty Disallow matches nothing)
        paths = ["/", "/admin/", "/tmp", "/search"]
        for n in range(200):
            groups = []
            star_used = False
            for _ in range(rng.randint(1, 3)):
                # one group at most may name '*': robotparser only reads the first such group while
                # RFC 9309 merges them, so the two references only agree on single-'*' files
                ua = rng.sample([a for a in agents if not (star_used and a == "*")], rng.randint(1, 2))
                star_used = star_used or "*" in ua
                rules = ["Disallow: %s" % rng.choice(paths) for _ in range(rng.randint(1, 3))]
                groups.append("\n".join(["User-agent: %s" % a for a in ua] + rules))
            text = "\n\n".join(groups) + "\n"
            rp = urllib.robotparser.RobotFileParser()
            rp.parse(text.splitlines())
            blocked = not rp.can_fetch("SomeCrawler/1.0", "https://%s/" % HOST)
            with self.subTest(n=n, robots=text):
                code, f = audit({"/robots.txt": text, "/.well-known/security.txt": good_security_txt()},
                                "--no-url-checks")
                flagged = any("for every crawler" in m for m in problems(f, "robots.txt"))
                self.assertEqual(flagged, blocked, text)


if __name__ == "__main__":
    unittest.main()
