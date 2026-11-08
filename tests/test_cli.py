"""End-to-end CLI tests via subprocess (no third-party test runner needed)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GOOD = os.path.join(ROOT, "examples", "good")
BAD = os.path.join(ROOT, "examples", "bad")

RFC_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
RFC_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def cli(*args: str):
    env = dict(os.environ)
    env["PYTHONPATH"] = ROOT + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-m", "grantscope", *args],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=60,
    )


class CliTests(unittest.TestCase):
    def test_version(self):
        r = cli("version")
        self.assertEqual(0, r.returncode)
        self.assertIn("GrantScope 1.0.0", r.stdout)

    def test_rules_json(self):
        r = cli("rules", "--format", "json")
        self.assertEqual(0, r.returncode)
        self.assertEqual(53, len(json.loads(r.stdout)))

    def test_rules_category_filter(self):
        r = cli("rules", "--category", "PKCE")
        self.assertIn("GS301", r.stdout)
        self.assertNotIn("GS101", r.stdout)

    def test_clean_bundle_passes_default_gate(self):
        r = cli("audit", GOOD, "--no-color", "--fail-on", "high")
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)
        self.assertIn("No findings", r.stdout)

    def test_bad_bundle_fails_critical_gate(self):
        r = cli("audit", BAD, "--no-color", "--fail-on", "critical", "--quiet")
        self.assertEqual(1, r.returncode)
        self.assertIn("GS102", r.stdout)

    def test_fail_on_never_always_succeeds(self):
        r = cli("audit", BAD, "--no-color", "--fail-on", "never")
        self.assertEqual(0, r.returncode)

    def test_implicit_audit_subcommand(self):
        r = cli(GOOD, "--no-color", "--fail-on", "never")
        self.assertEqual(0, r.returncode)
        self.assertIn("No findings", r.stdout)

    def test_sarif_output_to_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "report.sarif")
            r = cli("audit", BAD, "--format", "sarif", "--output", out,
                    "--fail-on", "never")
            self.assertEqual(0, r.returncode, r.stderr)
            with open(out, encoding="utf-8") as handle:
                data = json.load(handle)
            self.assertEqual("2.1.0", data["version"])
            self.assertTrue(data["runs"][0]["results"])

    def test_no_color_has_no_ansi(self):
        r = cli("audit", BAD, "--no-color", "--fail-on", "never")
        self.assertNotIn("\033[", r.stdout)

    def test_missing_input_returns_usage_error(self):
        r = cli("audit", "/definitely/not/here", "--fail-on", "never")
        self.assertEqual(2, r.returncode)
        self.assertIn("does not exist", r.stderr)

    def test_pkce_generate_json(self):
        r = cli("pkce", "--generate", "43", "--json")
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)
        data = json.loads(r.stdout)
        self.assertEqual(43, len(data["code_verifier"]))
        self.assertEqual(43, len(data["code_challenge"]))
        self.assertTrue(data["verifier_valid"])

    def test_pkce_verify_known_vector(self):
        ok = cli("pkce", "--verifier", RFC_VERIFIER, "--challenge", RFC_CHALLENGE)
        self.assertEqual(0, ok.returncode)
        self.assertIn("challenge matches      : True", ok.stdout)
        bad = cli("pkce", "--verifier", RFC_VERIFIER, "--challenge", "A" * 43)
        self.assertEqual(1, bad.returncode)
        self.assertIn("challenge matches      : False", bad.stdout)

    def test_pkce_requires_verifier(self):
        r = cli("pkce")
        self.assertEqual(2, r.returncode)

    def test_top_level_version_flag(self):
        r = cli("--version")
        self.assertEqual(0, r.returncode)
        self.assertIn("1.0.0", r.stdout)


if __name__ == "__main__":
    unittest.main()
