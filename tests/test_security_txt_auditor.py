"""End-to-end tests for security_txt_auditor.py.

The tool only speaks https://, so each test serves its robots.txt /
security.txt / sitemap fixtures from a real local HTTPS server (cert made with
the openssl CLI, trusted through SSL_CERT_FILE) and runs the tool unmodified as
a subprocess against "localhost:<port>" -- the same code path as a real domain.
"""
import datetime
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(os.path.dirname(HERE), "security_txt_auditor.py")

# path -> (status, body); replaced per test
ROUTES = {}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        route = ROUTES.get(self.path, (404, "not found"))
        status, body = route[0], route[1]
        ctype = route[2] if len(route) > 2 else "text/plain; charset=utf-8"
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
    CERT = os.path.join(TMP, "cert.pem")
    key = os.path.join(TMP, "key.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", CERT,
                    "-days", "2", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"],
                   check=True, capture_output=True)
    SERVER = HTTPServer(("127.0.0.1", 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, key)
    SERVER.socket = ctx.wrap_socket(SERVER.socket, server_side=True)
    HOST = "localhost:%d" % SERVER.server_address[1]
    threading.Thread(target=SERVER.serve_forever, daemon=True).start()


def tearDownModule():
    SERVER.shutdown()
    shutil.rmtree(TMP, ignore_errors=True)


def run(*args):
    env = dict(os.environ, SSL_CERT_FILE=CERT)
    return subprocess.run([sys.executable, TOOL] + list(args), capture_output=True, text=True,
                          env=env, timeout=120)


def future(days=200):
    return (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days)).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def past(days=10):
    return future(-days)


GOOD_SECTXT = "Contact: mailto:security@example.test\nContact: https://example.test/report\nExpires: %s\n"


def canonical():
    return "Canonical: https://%s/.well-known/security.txt\n" % HOST


class Base(unittest.TestCase):
    def audit(self, routes, target=None, code=None, args=()):
        ROUTES.clear()
        ROUTES.update(routes)
        p = run(*args, target or HOST)
        if code is not None:
            self.assertEqual(p.returncode, code, p.stdout + p.stderr)
        self.assertIn(p.returncode, (0, 1, 2), p.stderr)
        self.last_code = p.returncode
        return p.stdout

    def lines(self, out, level, category):
        return [l for l in out.splitlines() if ("[%-5s] %s:" % (level, category)) in l]


class TestRobots(Base):
    def test_missing_robots_is_info(self):
        out = self.audit({})
        self.assertTrue(any("not present" in l for l in self.lines(out, "INFO", "robots.txt")), out)

    def test_empty_robots_warns(self):
        out = self.audit({"/robots.txt": (200, "  \n")})
        self.assertTrue(any("present but empty" in l for l in self.lines(out, "WARN", "robots.txt")), out)

    def test_unexpected_status_warns(self):
        out = self.audit({"/robots.txt": (500, "boom")})
        self.assertTrue(any("unexpected HTTP 500" in l for l in self.lines(out, "WARN", "robots.txt")), out)

    def test_disallow_all_warns(self):
        out = self.audit({"/robots.txt": (200, "User-agent: *\nDisallow: /\n")})
        self.assertTrue(any("Disallow: /" in l for l in self.lines(out, "WARN", "robots.txt")), out)

    def test_ok_robots_and_sitemaps_checked(self):
        robots = ("User-agent: *\nDisallow: /admin\nSitemap: https://%s/sitemap.xml\n"
                  "Sitemap: https://%s/missing-sitemap.xml\n" % (HOST, HOST))
        out = self.audit({"/robots.txt": (200, robots), "/sitemap.xml": (200, "<urlset/>")})
        self.assertTrue(any("does not block all crawlers" in l for l in self.lines(out, "OK", "robots.txt")), out)
        self.assertTrue(any("sitemap reachable" in l and "/sitemap.xml" in l
                            for l in self.lines(out, "OK", "robots.txt")), out)
        self.assertTrue(any("HTTP 404" in l and "missing-sitemap.xml" in l
                            for l in self.lines(out, "WARN", "robots.txt")), out)

    def test_unreachable_host_is_error(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        ROUTES.clear()
        p = run("localhost:%d" % port)
        self.assertEqual(p.returncode, 2, p.stderr)
        self.assertTrue(self.lines(p.stdout, "ERROR", "robots.txt"), p.stdout)
        self.assertTrue(any("skipped" in l for l in self.lines(p.stdout, "ERROR", "security.txt")), p.stdout)


class TestSecurityTxt(Base):
    def test_missing_everywhere_is_info(self):
        out = self.audit({"/robots.txt": (200, "User-agent: *\n")}, code=1)
        self.assertTrue(any("not present at either standard location" in l
                            for l in self.lines(out, "WARN", "security.txt")), out)

    def test_good_file_at_well_known(self):
        out = self.audit({"/.well-known/security.txt": (200, GOOD_SECTXT % future() + canonical())}, code=0)
        self.assertTrue(any("found at https://%s/.well-known/security.txt" % HOST in l
                            for l in self.lines(out, "OK", "security.txt")), out)
        self.assertTrue(any("not yet expired" in l for l in self.lines(out, "OK", "security.txt")), out)
        self.assertEqual(self.lines(out, "WARN", "security.txt"), [], out)
        self.assertFalse(any("legacy" in l or "-only" in l for l in self.lines(out, "INFO", "security.txt")), out)

    def test_missing_contact_and_expires(self):
        out = self.audit({"/.well-known/security.txt": (200, "Policy: https://example.test/policy\n")})
        warns = " ".join(self.lines(out, "WARN", "security.txt"))
        self.assertIn("missing required 'Contact:'", warns)
        self.assertIn("missing required 'Expires:'", warns)

    def test_expired_file_warns(self):
        out = self.audit({"/.well-known/security.txt": (200, GOOD_SECTXT % past())})
        self.assertTrue(any("has PASSED" in l for l in self.lines(out, "WARN", "security.txt")), out)

    def test_unparseable_or_timezone_less_expires_warns(self):
        for bad in ("next year", "2099-01-01T00:00:00"):
            out = self.audit({"/.well-known/security.txt": (200, GOOD_SECTXT % bad)})
            self.assertTrue(any("not an RFC 3339 date-time" in l and bad in l
                                for l in self.lines(out, "WARN", "security.txt")), out)

    def test_legacy_location_only(self):
        out = self.audit({"/security.txt": (200, GOOD_SECTXT % future())}, code=0)
        self.assertTrue(any("found at https://%s/security.txt" % HOST in l
                            for l in self.lines(out, "OK", "security.txt")), out)
        self.assertTrue(any("only found at legacy /security.txt" in l
                            for l in self.lines(out, "INFO", "security.txt")), out)

    def test_empty_well_known_falls_back_to_legacy(self):
        out = self.audit({"/.well-known/security.txt": (200, "\n"), "/security.txt": (200, GOOD_SECTXT % future())})
        self.assertTrue(any("only found at legacy" in l for l in self.lines(out, "INFO", "security.txt")), out)

    def test_contact_scheme_checks(self):
        exp = "Expires: %s\n" % future()
        out = self.audit({"/.well-known/security.txt": (200, "Contact: mailto:sec@example.test\n" + exp)})
        self.assertTrue(any("email-only" in l for l in self.lines(out, "INFO", "security.txt")), out)
        out = self.audit({"/.well-known/security.txt": (200, "Contact: https://example.test/sec\n" + exp)})
        self.assertTrue(any("web-only" in l for l in self.lines(out, "INFO", "security.txt")), out)
        out = self.audit({"/.well-known/security.txt": (200, "Contact: security@example.test\n" + exp)})
        self.assertTrue(any("not a mailto:/https:/tel: URI" in l and "security@example.test" in l
                            for l in self.lines(out, "WARN", "security.txt")), out)

    def test_expires_more_than_a_year_out_or_repeated(self):
        out = self.audit({"/.well-known/security.txt": (200, GOOD_SECTXT % future(400))}, code=1)
        self.assertTrue(any("more than a year out" in l for l in self.lines(out, "WARN", "security.txt")), out)
        body = GOOD_SECTXT % future() + "Expires: %s\n" % future(10)
        out = self.audit({"/.well-known/security.txt": (200, body)}, code=1)
        self.assertTrue(any("appears 2 times" in l for l in self.lines(out, "WARN", "security.txt")), out)

    def test_content_type(self):
        body = GOOD_SECTXT % future()
        out = self.audit({"/.well-known/security.txt": (200, body, "text/html")}, code=1)
        self.assertTrue(any("served as 'text/html'" in l for l in self.lines(out, "WARN", "security.txt")), out)
        out = self.audit({"/.well-known/security.txt": (200, body, "text/plain")}, code=0)
        self.assertTrue(any("no charset=utf-8" in l for l in self.lines(out, "INFO", "security.txt")), out)

    def test_canonical(self):
        out = self.audit({"/.well-known/security.txt": (200, GOOD_SECTXT % future())}, code=0)
        self.assertTrue(any("no 'Canonical:' field" in l for l in self.lines(out, "INFO", "security.txt")), out)
        body = GOOD_SECTXT % future() + "Canonical: https://other.example/.well-known/security.txt\n"
        out = self.audit({"/.well-known/security.txt": (200, body)}, code=1)
        self.assertTrue(any("none of the Canonical URLs" in l for l in self.lines(out, "WARN", "security.txt")), out)
        out = self.audit({"/.well-known/security.txt": (200, GOOD_SECTXT % future() + canonical())}, code=0)
        self.assertTrue(any("Canonical matches" in l for l in self.lines(out, "OK", "security.txt")), out)

    def test_linked_urls_and_unknown_fields(self):
        body = (GOOD_SECTXT % future() + canonical() + "Policy: https://%s/policy\n" % HOST
                + "Encryption: https://%s/missing-key.asc\n" % HOST + "Hiring: http://%s/jobs\n" % HOST
                + "Encryption: openpgp4fpr:5f2de5521c63a801ab59ccb603d49de44b29100f\nFavourite-Colour: blue\n")
        out = self.audit({"/.well-known/security.txt": (200, body), "/policy": (200, "policy")}, code=1)
        self.assertTrue(any("Policy: https://%s/policy reachable" % HOST in l for l in self.lines(out, "OK", "security.txt")), out)
        warns = " ".join(self.lines(out, "WARN", "security.txt"))
        self.assertIn("missing-key.asc answers HTTP 404", warns)
        self.assertIn("uses http://", warns)
        self.assertNotIn("openpgp4fpr", warns)
        self.assertTrue(any("unknown field(s): favourite-colour" in l for l in self.lines(out, "INFO", "security.txt")), out)
        out = self.audit({"/.well-known/security.txt": (200, body)}, args=("--no-url-checks",))
        self.assertNotIn("missing-key.asc answers", out)

    def test_pgp_signed_file_is_parsed(self):
        inner = GOOD_SECTXT % future() + canonical() + "- Policy: https://%s/policy\n" % HOST
        body = ("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n" + inner
                + "-----BEGIN PGP SIGNATURE-----\n\niQIzBAEBCgAdFiEE\n=abcd\n-----END PGP SIGNATURE-----\n")
        out = self.audit({"/.well-known/security.txt": (200, body), "/policy": (200, "p")}, code=0)
        self.assertTrue(any("cleartext-signed" in l for l in self.lines(out, "OK", "security.txt")), out)
        self.assertTrue(any("Policy: https://%s/policy reachable" % HOST in l for l in self.lines(out, "OK", "security.txt")), out)
        self.assertFalse(any("unknown field" in l for l in out.splitlines()), out)
        out = self.audit({"/.well-known/security.txt": (200, GOOD_SECTXT % future())})
        self.assertTrue(any("not digitally signed" in l for l in self.lines(out, "INFO", "security.txt")), out)


class TestCli(Base):
    def test_multiple_domains_and_url_forms(self):
        ROUTES.clear()
        ROUTES["/.well-known/security.txt"] = (200, GOOD_SECTXT % future() + canonical())
        p = run(HOST, "https://%s/" % HOST, "http://%s" % HOST)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.count("=== %s ===" % HOST), 3, p.stdout)
        self.assertEqual(p.stdout.count("not yet expired"), 3, p.stdout)

    def test_json_and_fail_on_gates(self):
        ROUTES.clear()
        ROUTES["/.well-known/security.txt"] = (200, GOOD_SECTXT % future())  # only INFO-level notes
        p = run("--json", HOST)
        self.assertEqual(p.returncode, 0, p.stdout)
        data = json.loads(p.stdout)
        self.assertEqual(data["exit_code"], 0)
        self.assertEqual(data["results"][0]["domain"], HOST)
        levels = {f["level"] for f in data["results"][0]["findings"]}
        self.assertEqual(levels, {"OK", "INFO"})
        self.assertEqual(run("--fail-on", "info", HOST).returncode, 1)
        ROUTES["/.well-known/security.txt"] = (200, GOOD_SECTXT % past())
        p = run("--json", HOST)
        self.assertEqual(p.returncode, 1)
        self.assertEqual(json.loads(p.stdout)["exit_code"], 1)
        self.assertEqual(run("--fail-on", "never", HOST).returncode, 0)
        p = run(HOST)
        self.assertIn("FAIL: findings at or above WARN (exit 1)", p.stdout)

    def test_version(self):
        p = run("--version")
        self.assertEqual(p.returncode, 0)
        self.assertRegex(p.stdout, r"^security-txt-auditor \d+\.\d+\.\d+$")

    def test_no_domain_is_usage_error(self):
        p = run()
        self.assertEqual(p.returncode, 2)
        self.assertIn("usage:", p.stderr)

    def test_help(self):
        p = run("--help")
        self.assertEqual(p.returncode, 0)
        self.assertIn("security.txt", p.stdout)


class TestExpiresParser(unittest.TestCase):
    """RFC 3339 section 5.6 date-times, the only Expires form RFC 9116 allows (mutation testing showed
    the parser's offset/leap-second/validation branches were never pinned down)."""

    def test_rfc3339_forms(self):
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        import security_txt_auditor as st
        utc = datetime.timezone.utc
        ok = {
            "2026-10-17T12:00:00Z": datetime.datetime(2026, 10, 17, 12, 0, 0, tzinfo=utc),
            "2026-10-17t12:00:00z": datetime.datetime(2026, 10, 17, 12, 0, 0, tzinfo=utc),
            " 2026-10-17T12:00:00.123456Z ": datetime.datetime(2026, 10, 17, 12, 0, 0, tzinfo=utc),
            "2026-10-17T12:00:00+05:30": datetime.datetime(2026, 10, 17, 6, 30, 0, tzinfo=utc),
            "2026-10-17T12:00:00-08:00": datetime.datetime(2026, 10, 17, 20, 0, 0, tzinfo=utc),
            "2026-10-17T12:00:00+23:59": datetime.datetime(2026, 10, 16, 12, 1, 0, tzinfo=utc),
            "2026-12-31T23:59:60Z": datetime.datetime(2027, 1, 1, 0, 0, 0, tzinfo=utc),  # leap second
            "2026-10-17T12:34:56+00:00": datetime.datetime(2026, 10, 17, 12, 34, 56, tzinfo=utc),
        }
        for raw, want in ok.items():
            got = st.parse_expires(raw)
            self.assertEqual(got, want, raw)
            self.assertIsNotNone(got.tzinfo, raw)
        self.assertEqual(st.parse_expires("2026-10-17T12:00:00+05:30").utcoffset(), datetime.timedelta(hours=5, minutes=30))
        self.assertEqual(st.parse_expires("2026-10-17T12:00:00-08:00").utcoffset(), datetime.timedelta(hours=-8))
        for bad in ("2026-10-17 12:00:00Z", "2026-10-17T12:00:00", "2026-10-17T12:00Z", "2026-10-17T12:00:00+24:00",
                    "2026-13-01T00:00:00Z", "2026-02-30T00:00:00Z", "2026-10-17T12:00:00+0530", "Thu, 17 Oct 2026",
                    "2026-10-17", "", "2026-10-17T12:00:00Zjunk"):
            with self.assertRaises(ValueError, msg=bad):
                st.parse_expires(bad)


if __name__ == "__main__":
    unittest.main()
