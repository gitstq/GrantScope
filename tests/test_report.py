"""Renderer tests: text, Markdown, JSON and SARIF 2.1.0."""

from __future__ import annotations

import json
import os
import unittest

from grantscope import audit_paths, render
from grantscope.report import FORMATS

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BAD = os.path.join(ROOT, "examples", "bad")


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.report = audit_paths([BAD])

    def test_text_contains_rule_ids_and_no_ansi_when_disabled(self):
        text = render(self.report, "text", color=False)
        self.assertIn("GS102", text)
        self.assertIn("FINDINGS:", text)
        self.assertNotIn("\033[", text)
        self.assertIn("offline static auditor", text)

    def test_text_verbose_flag_changes_detail(self):
        short = render(self.report, "text", color=False, verbose=False)
        long = render(self.report, "text", color=False, verbose=True)
        self.assertLess(len(short), len(long))
        self.assertIn("fix      :", long)
        self.assertNotIn("fix      :", short)

    def test_json_roundtrip(self):
        data = json.loads(render(self.report, "json"))
        self.assertEqual("GrantScope", data["tool"])
        self.assertEqual(len(self.report.findings), data["summary"]["total"])
        self.assertEqual(len(self.report.findings), len(data["findings"]))
        self.assertTrue(all("rule_id" in f for f in data["findings"]))

    def test_markdown_has_table_header_and_rows(self):
        md = render(self.report, "markdown")
        self.assertIn("| Rule | Severity | Category | Location | Message |", md)
        self.assertIn("| `GS102` |", md)

    def test_sarif_structure(self):
        sarif = json.loads(render(self.report, "sarif"))
        self.assertEqual("2.1.0", sarif["version"])
        run = sarif["runs"][0]
        self.assertEqual("GrantScope", run["tool"]["driver"]["name"])
        self.assertEqual(53, len(run["tool"]["driver"]["rules"]))
        self.assertEqual(len(self.report.findings), len(run["results"]))
        for result in run["results"]:
            self.assertIn("ruleId", result)
            self.assertIn("level", result)
            self.assertTrue(result["locations"])
        self.assertIn("$schema", sarif)
        uris = [r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                for r in run["results"]]
        self.assertTrue(any(u.endswith("examples/bad/discovery.json") for u in uris), uris)

    def test_clean_report_text_says_no_findings(self):
        from grantscope import audit

        clean = audit([])
        self.assertIn("No findings", render(clean, "text", color=False))
        self.assertIn("All applicable rules passed", render(clean, "markdown"))

    def test_unknown_format_raises(self):
        with self.assertRaises(ValueError):
            render(self.report, "xml")

    def test_formats_constant(self):
        self.assertEqual(("text", "markdown", "json", "sarif"), FORMATS)


if __name__ == "__main__":
    unittest.main()
