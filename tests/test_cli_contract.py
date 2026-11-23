"""Shared CLI contract (docs/CLI-CONTRACT.md): exit codes, --json schema, --quiet, stderr for errors.

Runs the tool as a subprocess against the same local HTTPS fixture server the other tests use.
"""
import io
import json
import os
import sys
import unittest
from contextlib import redirect_stderr
from unittest import mock

import contract_support as cs
import test_security_txt_auditor as T

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOL = T.TOOL
sys.path.insert(0, ROOT)
import security_txt_auditor as tool  # noqa: E402

SCHEMA = cs.load_schema(ROOT, "security-txt-auditor")


def setUpModule():
    T.setUpModule()


def tearDownModule():
    T.tearDownModule()


def cli(*args):
    return cs.run_cli(TOOL, args, env={"SSL_CERT_FILE": T.CERT})


def clean():
    T.ROUTES.clear()
    T.ROUTES["/.well-known/security.txt"] = (200, T.GOOD_SECTXT % T.future())


def findings():
    T.ROUTES.clear()
    T.ROUTES["/.well-known/security.txt"] = (200, T.GOOD_SECTXT % T.past())


UNREACHABLE = "localhost:1"  # nothing listens there: connection refused, no real network


class TestExitCodes(unittest.TestCase):
    def test_clean_is_0(self):
        clean()
        self.assertEqual(cli(T.HOST)[0], 0)

    def test_findings_is_1(self):
        findings()
        self.assertEqual(cli(T.HOST)[0], 1)

    def test_bad_args_is_2_with_message_on_stderr(self):
        for args in ((), ("--no-such-flag", "example.test"), ("--fail-on", "bogus", "example.test")):
            rc, out, err = cli(*args)
            self.assertEqual(rc, 2, args)
            self.assertEqual(out, "")
            self.assertIn("usage:", err)

    def test_unreachable_target_keeps_documented_legacy_code_2(self):
        rc, out, err = cli(UNREACHABLE)
        self.assertEqual(rc, 2)
        self.assertIn("host unreachable", out)

    def test_unexpected_error_is_3_on_stderr_not_a_traceback_exit_1(self):
        buf = io.StringIO()
        with mock.patch.object(tool, "_main", side_effect=RuntimeError("boom")), redirect_stderr(buf):
            self.assertEqual(tool.main([UNREACHABLE]), 3)
        self.assertIn("RuntimeError: boom", buf.getvalue())


class TestJson(unittest.TestCase):
    def check(self, args, code):
        rc, out, err = cli("--json", *args)
        self.assertEqual(rc, code, err)
        doc = json.loads(out)  # exactly one JSON document, nothing else on stdout
        self.assertEqual(cs.validate(doc, SCHEMA), [])
        self.assertEqual(doc["exit_code"], rc)
        self.assertEqual(doc["schema_version"], 1)
        self.assertEqual(doc["tool"], "security-txt-auditor")
        self.assertEqual(doc["version"], tool.__version__)
        return doc

    def test_clean(self):
        clean()
        self.check((T.HOST,), 0)

    def test_findings(self):
        findings()
        doc = self.check((T.HOST,), 1)
        self.assertTrue(any(f["level"] == "WARN" for f in doc["results"][0]["findings"]))

    def test_unreachable(self):
        self.check((UNREACHABLE,), 2)

    def test_usage_error_leaves_stdout_empty(self):
        rc, out, err = cli("--json")
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("usage:", err)

    def test_schema_rejects_a_document_without_the_contract_keys(self):
        self.assertNotEqual(cs.validate({"results": []}, SCHEMA), [])
        self.assertNotEqual(cs.validate({"schema_version": 1, "tool": "x", "version": "1", "exit_code": 9,
                                         "fail_on": "warn", "results": []}, SCHEMA), [])


class TestQuiet(unittest.TestCase):
    def test_quiet_prints_nothing_but_keeps_exit_code(self):
        for setup, code, target in ((clean, 0, T.HOST), (findings, 1, T.HOST), (clean, 2, UNREACHABLE)):
            setup()
            for extra in ((), ("--json",)):
                for flag in ("--quiet", "-q"):
                    rc, out, err = cli(flag, *(extra + (target,)))
                    self.assertEqual((rc, out), (code, ""), (flag, extra, target))

    def test_without_quiet_the_report_is_printed(self):
        clean()
        self.assertIn("===", cli(T.HOST)[1])


if __name__ == "__main__":
    unittest.main()
