"""End-to-end tests for security_txt_auditor.py.

The tool only speaks https://, so each test serves its robots.txt /
security.txt / sitemap fixtures from a real local HTTPS server (cert made with
the openssl CLI, trusted through SSL_CERT_FILE) and runs the tool unmodified as
a subprocess against "localhost:<port>" -- the same code path as a real domain.
"""
import datetime
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
        status, body = ROUTES.get(self.path, (404, "not found"))
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
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


class Base(unittest.TestCase):
    def audit(self, routes, target=None):
        ROUTES.clear()
        ROUTES.update(routes)
        p = run(target or HOST)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)  # reporting tool: always 0
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
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertTrue(self.lines(p.stdout, "ERROR", "robots.txt"), p.stdout)


class TestSecurityTxt(Base):
    def test_missing_everywhere_is_info(self):
        out = self.audit({"/robots.txt": (200, "User-agent: *\n")})
        self.assertTrue(any("not present at either standard location" in l
                            for l in self.lines(out, "INFO", "security.txt")), out)

    def test_good_file_at_well_known(self):
        out = self.audit({"/.well-known/security.txt": (200, GOOD_SECTXT % future())})
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
        out = self.audit({"/security.txt": (200, GOOD_SECTXT % future())})
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


class TestCli(Base):
    def test_multiple_domains_and_url_forms(self):
        ROUTES.clear()
        ROUTES["/.well-known/security.txt"] = (200, GOOD_SECTXT % future())
        p = run(HOST, "https://%s/" % HOST, "http://%s" % HOST)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.count("=== %s ===" % HOST), 3, p.stdout)
        self.assertEqual(p.stdout.count("not yet expired"), 3, p.stdout)

    def test_no_domain_is_usage_error(self):
        p = run()
        self.assertEqual(p.returncode, 2)
        self.assertIn("usage:", p.stderr)

    def test_help(self):
        p = run("--help")
        self.assertEqual(p.returncode, 0)
        self.assertIn("security.txt", p.stdout)


if __name__ == "__main__":
    unittest.main()
